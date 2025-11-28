#!/usr/bin/env python3
# SoterG Stratum Proxy
# - Uses TIME_MASK to derive x12rt rotations from masked timestamp
# - Sends miners explicit rotations and selector derived from masked time
# - Constructs header, coinbase, merkle, and submits blocks to node
# - Does NOT validate PoW (left to miners/node). Optional local hashing can be added later.

import asyncio
import json
import time
import sys
import urllib.parse
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Set, List, Optional, Tuple
from datetime import datetime

import base58
from aiohttp import ClientSession
from aiorpcx import RPCSession, JSONRPCConnection, Request, serve_rs, handler_invocation, RPCError, TaskGroup, JSONRPCv1
from hashlib import sha256

# -----------------------------
# SOTERGV1 time-based x12rt selection (embedded)
# -----------------------------

TIME_MASK = 0xFFFFFFA0  # 96s bitmask

def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()

def hash_time_masked(n_time: int) -> bytes:
    """
    Produces the 32-byte LE SHA256d of the masked time (as 4-byte LE).
    Matches C++: uint256 hashTime = Hash(BEGIN(nTimeSoterG), END(nTimeSoterG));
    """
    n_time_masked = n_time & TIME_MASK
    return dsha256(n_time_masked.to_bytes(4, 'little'))

def get_nibble_le(selector_le32: bytes, pos: int) -> int:
    """
    Read nibble from a 32-byte little-endian selector (C++ uint256 style).
    pos is 0..63 (nibble index).
    """
    if pos < 0 or pos >= 64:
        raise ValueError("pos out of range")
    byte_index = pos // 2
    low = (pos % 2) == 0
    b = selector_le32[byte_index]
    return (b & 0x0F) if low else ((b >> 4) & 0x0F)

def get_hash_selection_from_time(selector_le32: bytes, index: int) -> int:
    """
    Mirrors C++ GetHashSelection(PrevBlockHash, index) but uses the selector
    from masked time hash. Bounds check, fast path, slow path, fallback.
    """
    assert 0 <= index < 12
    START = 48
    MASK = 0xF
    pos = START + (index & MASK)
    nibble = get_nibble_le(selector_le32, pos)
    if nibble < 12:
        return nibble
    for i in range(1, 16):
        pos2 = START + ((index + i) & MASK)
        nibble2 = get_nibble_le(selector_le32, pos2)
        if nibble2 < 12:
            return nibble2
    return nibble % 12

def compute_rotations_for_time(n_time: int) -> list:
    """
    Return the 12 algo indices for a given nTime (masked).
    """
    selector = hash_time_masked(n_time)  # 32-byte LE
    return [get_hash_selection_from_time(selector, i) for i in range(12)]

# -----------------------------
# Utilities
# -----------------------------

def var_int(i: int) -> bytes:
    assert i >= 0
    if i < 0xfd:
        return i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')

def op_push(i: int) -> bytes:
    if i < 0x4C:
        return i.to_bytes(1, 'little')
    elif i <= 0xff:
        return b'\x4c' + i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\x4d' + i.to_bytes(2, 'little')
    else:
        return b'\x4e' + i.to_bytes(4, 'little')

def merkle_from_txids(txids: List[bytes]) -> bytes:
    if not txids:
        return dsha256(b'')
    if len(txids) == 1:
        return txids[0]
    work = txids[:]
    while len(work) > 1:
        if len(work) % 2 == 1:
            work.append(work[-1])
        work = [dsha256(l + r) for l, r in zip(work[0::2], work[1::2])]
    return work[0]

# -----------------------------
# State
# -----------------------------

@dataclass
class TemplateState:
    height: int = -1
    timestamp: int = -1
    address: Optional[str] = None
    bits: Optional[str] = None
    target: Optional[str] = None
    headerHash: Optional[str] = None  # optional local display hash (proxy does not validate)
    version: int = -1
    prevHash: Optional[bytes] = None
    externalTxs: List[str] = field(default_factory=list)
    seedHash: Optional[bytes] = None
    header: Optional[bytes] = None
    coinbase_tx: Optional[bytes] = None
    coinbase_txid: Optional[bytes] = None
    current_commitment: Optional[str] = None
    new_sessions: Set[RPCSession] = field(default_factory=set)
    all_sessions: Set[RPCSession] = field(default_factory=set)
    job_counter: int = 0
    bits_counter: int = 0

    # x12rt extras
    x12rt_rotations: Optional[List[int]] = None
    x12rt_selector_le: Optional[bytes] = None

    def build_block(self, nonce_le_hex: str) -> str:
        """
        nonce_le_hex: 8-byte nonce in little-endian hex
        """
        assert self.header is not None
        assert self.coinbase_tx is not None
        block = (
            self.header.hex() +
            nonce_le_hex +
            var_int(len(self.externalTxs) + 1).hex() +
            self.coinbase_tx.hex() +
            ''.join(self.externalTxs)
        )
        return block

# -----------------------------
# Old state ring buffer
# -----------------------------

def add_old_state_to_queue(queue: Tuple[List[str], dict], state: TemplateState, drop_after: int):
    jid = hex(state.job_counter)[2:]
    if jid in queue[1]:
        return
    queue[0].append(jid)
    queue[1][jid] = deepcopy(state)
    while len(queue[0]) > drop_after:
        oldest = queue[0].pop(0)
        queue[1].pop(oldest, None)

def lookup_old_state(queue: Tuple[List[str], dict], jid: str) -> Optional[TemplateState]:
    return queue[1].get(jid)

# -----------------------------
# Session
# -----------------------------

hashratedict = {}

class StratumSession(RPCSession):
    def __init__(self, state: TemplateState, old_states, testnet: bool, node_url: str, node_username: str, node_password: str, node_port: int, transport):
        connection = JSONRPCConnection(JSONRPCv1)
        super().__init__(transport, connection=connection)
        self._state = state
        self._testnet = testnet
        self._old_states = old_states
        self._node_url = node_url
        self._node_username = node_username
        self._node_password = node_password
        self._node_port = node_port

        self.handlers = {
            'mining.subscribe': self.handle_subscribe,
            'mining.authorize': self.handle_authorize,
            'mining.submit': self.handle_submit,
            'eth_submitHashrate': self.handle_eth_submitHashrate,
        }

    async def handle_request(self, request):
        if isinstance(request, Request):
            handler = self.handlers.get(request.method)
            if not handler:
                return
        else:
            return
        return await handler_invocation(handler, request)()

    async def connection_lost(self):
        worker = str(self).strip('>').split()[3]
        print(f'Connection lost: {worker}')
        hashratedict.pop(worker, None)
        self._state.new_sessions.discard(self)
        self._state.all_sessions.discard(self)
        return await super().connection_lost()

    async def handle_subscribe(self, *args):
        if self not in self._state.all_sessions:
            self._state.new_sessions.add(self)
        self._state.bits_counter += 1
        return [None, self._state.bits_counter.to_bytes(2, 'big').hex()]

    async def handle_authorize(self, username: str, password: str):
        address = username.split('.')[0]
        # Validate version byte: adjust to SOTER prefixes if different
        version = base58.b58decode_check(address)[0]
        expected = 66 if self._testnet else 63
        if version != expected:
            raise RPCError(20, f'Invalid address {address}')
        if not self._state.address:
            self._state.address = address
        return True

    async def handle_submit(self, worker: str, job_id: str, nonce_hex: str, header_hex: str):
        now = datetime.now()
        print('Possible solution')
        print(worker)
        print(job_id)
        print(header_hex)

        # Resolve state by job id
        state = self._state
        if job_id != hex(state.job_counter)[2:]:
            print('Old job submitted, trying old states')
            old_state = lookup_old_state(self._old_states, job_id)
            if old_state is not None:
                state = old_state
            else:
                raise RPCError(20, 'Miner submitted an old job that we did not have')

        # Nonce: miners usually send big-endian; convert to LE hex for block
        if nonce_hex[:2].lower() == '0x':
            nonce_hex = nonce_hex[2:]
        nonce_le_hex = bytes.fromhex(nonce_hex)[::-1].hex()

        block_hex = state.build_block(nonce_le_hex)
        data = {
            'jsonrpc': '2.0',
            'id': '0',
            'method': 'submitblock',
            'params': [block_hex]
        }

        async with ClientSession() as session:
            async with session.post(f'http://{self._node_username}:{self._node_password}@{self._node_url}:{self._node_port}', data=json.dumps(data)) as resp:
                json_resp = await resp.json()
                print(json_resp)
                if json_resp.get('error', None):
                    raise RPCError(20, json_resp['error'])

                result = json_resp.get('result', None)
                if result == 'inconclusive':
                    print('Valid block but inconclusive')
                elif result == 'duplicate':
                    print('Valid block but duplicate')
                elif result == 'duplicate-inconclusive':
                    print('Valid block but duplicate-inconclusive')
                elif result == 'inconclusive-not-best-prevblk':
                    print('Valid block but inconclusive-not-best-prevblk')

                if result not in (None, 'inconclusive', 'duplicate', 'duplicate-inconclusive', 'inconclusive-not-best-prevblk'):
                    raise RPCError(20, json_resp['result'])

        # Decode height from header
        block_height = int.from_bytes(bytes.fromhex(block_hex[(4+32+32+4+4)*2:(4+32+32+4+4+4)*2]), 'little', signed=False)
        msg = f'Found block (may or may not be accepted by the chain): {block_height}'
        print(msg)
        await self.send_notification('client.show_message', (msg,))
        return True

    async def handle_eth_submitHashrate(self, hashrate: str, clientid: str):
        data = {
            'jsonrpc': '2.0',
            'id': '0',
            'method': 'getmininginfo',
            'params': []
        }
        async with ClientSession() as session:
            async with session.post(f'http://{self._node_username}:{self._node_password}@{self._node_url}:{self._node_port}', data=json.dumps(data)) as resp:
                try:
                    json_obj = await resp.json()
                    if json_obj.get('error', None):
                        raise Exception(json_obj.get('error', None))
                    blocks_int = json_obj['result']['blocks']
                    difficulty_int = json_obj['result']['difficulty']
                    networkhashps_int = json_obj['result']['networkhashps']
                except Exception:
                    print('Failed to query mininginfo from node')
                    import traceback
                    traceback.print_exc()
                    return True

        hr = int(hashrate, 16)
        worker = str(self).strip('>').split()[3]
        hashratedict[worker] = hr

        totalHashrate = sum(hashratedict.values())
        print('----------------------------')
        for w, h in hashratedict.items():
            print(f'Reported Hashrate: {round(h / 1_000_000, 2)} Mh/s for ID: {w}')
        print('----------------------------')
        print(f'Total Reported Hashrate: {round(totalHashrate / 1_000_000, 2)} Mh/s')

        if self._testnet:
            print(f'Network Hashrate: {round(networkhashps_int / 1_000_000, 2)} Mh/s')
        else:
            print(f'Network Hashrate: {round(networkhashps_int / 1_000_000_000_000, 2)} Th/s')

        if totalHashrate != 0:
            TTF = difficulty_int * 2**32 / totalHashrate
            msg = f'Estimated time to find: {round(TTF) if self._testnet else round(TTF / 86400, 2)} {"seconds" if self._testnet else "days"}'
            print(msg)
            await self.send_notification('client.show_message', (msg,))
        else:
            print('Mining software has yet to send data')
        return True

# -----------------------------
# Updater
# -----------------------------

async def stateUpdater(state: TemplateState, old_states, drop_after, node_url: str, node_username: str, node_password: str, node_port: int):
    if not state.address:
        return
    data = {
        'jsonrpc': '2.0',
        'id': '0',
        'method': 'getblocktemplate',
        'params': []
    }
    async with ClientSession() as session:
        async with session.post(f'http://{node_username}:{node_password}@{node_url}:{node_port}', data=json.dumps(data)) as resp:
            try:
                json_obj = await resp.json()
                if json_obj.get('error', None):
                    raise Exception(json_obj.get('error', None))

                tpl = json_obj['result']
                version_int: int = tpl['version']
                height_int: int = tpl['height']
                bits_hex: str = tpl['bits']
                prev_hash_hex: str = tpl['previousblockhash']
                txs_list: List = tpl['transactions']
                coinbase_sats_int: int = tpl['coinbasevalue']
                witness_hex: str = tpl['default_witness_commitment']
                coinbase_flags_hex: str = tpl['coinbaseaux']['flags']
                target_hex: str = tpl['target']

                ts = int(time.time())
                new_witness = witness_hex != state.current_commitment
                state.current_commitment = witness_hex
                state.target = target_hex
                state.bits = bits_hex
                state.version = version_int
                state.prevHash = bytes.fromhex(prev_hash_hex)[::-1]  # LE

                new_block = False
                original_state = None

                if state.height == -1 or state.height != height_int:
                    original_state = deepcopy(state)
                    print('New block, update state')
                    new_block = True

                # Seed hash init/reset (placeholder; keep deterministic zero)
                if state.height == -1 or height_int > state.height:
                    if not state.seedHash:
                        seed_hash = bytes(32)
                        print(f'Initialized seedhash to {seed_hash.hex()}')
                        state.seedHash = seed_hash
                elif state.height > height_int:
                    seed_hash = bytes(32)
                    print(f'Reverted seedhash to {seed_hash.hex()}')
                    state.seedHash = seed_hash

                state.height = height_int

                # Update coinbase and merkle if new block, new witness, or 60s passed
                if new_block or new_witness or state.timestamp + 60 < ts:
                    if original_state is None:
                        original_state = deepcopy(state)

                    # BIP34 height push
                    bytes_needed_sub_1 = 0
                    while True:
                        if state.height <= (2**(7 + (8 * bytes_needed_sub_1))) - 1:
                            break
                        bytes_needed_sub_1 += 1
                    bip34_height = state.height.to_bytes(bytes_needed_sub_1 + 1, 'little')

                    # Arbitrary data
                    arbitrary_data = b'github.com/soteria/soterg-proxy'
                    coinbase_script = op_push(len(bip34_height)) + bip34_height + b'\0' + op_push(len(arbitrary_data)) + arbitrary_data
                    coinbase_txin = bytes(32) + b'\xff'*4 + var_int(len(coinbase_script)) + coinbase_script + b'\xff'*4

                    # Outputs
                    vout_to_miner = b'\x76\xa9\x14' + base58.b58decode_check(state.address)[1:] + b'\x88\xac'
                    foundation_addr = "SMy5NT6Qzfwsb6chSks284xugJfcWGhQU7"  # adjust if needed
                    vout_to_foundation = b'\xa9\x14' + base58.b58decode_check(foundation_addr)[1:] + b'\x87'
                    witness_vout = bytes.fromhex(witness_hex)

                    # Split shares deterministically
                    miner_share = coinbase_sats_int * 30 // 100
                    foundation_share = coinbase_sats_int - miner_share

                    state.coinbase_tx = (
                        int(1).to_bytes(4, 'little') +  # nVersion
                        b'\x00\x01' +                   # marker+flag (SegWit)
                        b'\x01' + coinbase_txin +       # 1 vin
                        b'\x03' +                       # 3 vout
                          miner_share.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner +
                          foundation_share.to_bytes(8, 'little') + op_push(len(vout_to_foundation)) + vout_to_foundation +
                          bytes(8) + op_push(len(witness_vout)) + witness_vout +
                        b'\x01\x20' + bytes(32) + bytes(4)  # witness for coinbase, locktime
                    )

                    coinbase_no_wit = (
                        int(1).to_bytes(4, 'little') +
                        b'\x01' + coinbase_txin +
                        b'\x03' +
                          miner_share.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner +
                          foundation_share.to_bytes(8, 'little') + op_push(len(vout_to_foundation)) + vout_to_foundation +
                          bytes(8) + op_push(len(witness_vout)) + witness_vout +
                        bytes(4)
                    )
                    state.coinbase_txid = dsha256(coinbase_no_wit)

                    # Merkle
                    txids = [state.coinbase_txid]
                    incoming_txs = []
                    for tx_data in txs_list:
                        incoming_txs.append(tx_data['data'])
                        txids.append(bytes.fromhex(tx_data['txid'])[::-1])
                    state.externalTxs = incoming_txs
                    merkle = merkle_from_txids(txids)

                    # Header (LE fields)
                    state.header = (
                        version_int.to_bytes(4, 'little') +
                        state.prevHash +         # LE prevhash
                        merkle +                 # digest bytes
                        ts.to_bytes(4, 'little') +
                        bytes.fromhex(bits_hex)[::-1] +
                        state.height.to_bytes(4, 'little')
                    )
                    state.timestamp = ts

                    # x12rt selector and rotations from masked timestamp
                    selector_le = hash_time_masked(ts)
                    rotations = [get_hash_selection_from_time(selector_le, i) for i in range(12)]
                    state.x12rt_selector_le = selector_le
                    state.x12rt_rotations = rotations

                    state.headerHash = None  # optional: compute local hash if we wire all 12 algos

                    state.job_counter += 1
                    add_old_state_to_queue(old_states, original_state, drop_after)

                    # Notify existing sessions
                    for session in state.all_sessions:
                        await notify_x12rt(session, state)

                # Notify new sessions
                for session in state.new_sessions:
                    state.all_sessions.add(session)
                    await notify_x12rt(session, state)
                state.new_sessions.clear()

            except Exception:
                print('Failed to query blocktemplate from node')
                import traceback
                traceback.print_exc()
                print('Sleeping for 1 minute.\nAny solutions found during this time may not be current.\nTry restarting the proxy.')
                await asyncio.sleep(60)

# -----------------------------
# Notify helper (x12rt-aware)
# -----------------------------

async def notify_x12rt(session: StratumSession, state: TemplateState):
    """
    Sends mining.set_target and mining.notify with x12rt payload:
    - selector_le: SHA256d(nTime & TIME_MASK) LE bytes
    - rotations: 12 indices computed via GetHashSelection over selector
    - header_le: 80-byte header without nonce
    """
    target_hex = state.target
    bits_hex = state.bits
    job_id = hex(state.job_counter)[2:]
    header_hash_hex = state.headerHash  # may be None
    seed_hex = state.seedHash.hex() if state.seedHash else bytes(32).hex()

    rotations = state.x12rt_rotations or [0] * 12
    selector_le_hex = (state.x12rt_selector_le or bytes(32)).hex()

    await session.send_notification('mining.set_target', (target_hex,))
    await session.send_notification(
        'mining.notify',
        (
            job_id,
            header_hash_hex,          # optional; miners should compute PoW themselves
            seed_hex,
            target_hex,
            True,
            state.height,
            bits_hex,
            {
                "algo": "x12rt",
                "selector_le": selector_le_hex,  # SHA256d(nTime & TIME_MASK), LE
                "rotations": rotations,          # 12 ints (0..11)
                "header_le": state.header.hex(), # 80-byte header hex (without nonce)
            }
        )
    )

# -----------------------------
# Main
# -----------------------------

if __name__ == '__main__':
    def check_bool(x) -> bool:
        if isinstance(x, str):
            return x.lower()[0] == 't'
        return bool(x)

    if len(sys.argv) < 7:
        print('arguments must be: proxy_port, node_ip, node_username, node_password, node_port, listen_externally, (testnet - optional)')
        sys.exit(0)

    proxy_port = int(sys.argv[1])
    node_url = str(sys.argv[2])
    node_username = urllib.parse.quote(str(sys.argv[3]), safe='')
    node_password = urllib.parse.quote(str(sys.argv[4]), safe='')
    node_port = int(sys.argv[5])
    should_listen_externaly = check_bool(sys.argv[6])
    testnet = False
    if len(sys.argv) > 7:
        testnet = check_bool(sys.argv[7])

    print('Starting SoterG stratum proxy')

    state = TemplateState()
    historical_states = ([], {})
    store = 20

    session_generator = lambda transport: StratumSession(state, historical_states, testnet, node_url, node_username, node_password, node_port, transport)

    async def updateState():
        while True:
            await stateUpdater(state, historical_states, store, node_url, node_username, node_password, node_port)
            await asyncio.sleep(0.1)

    async def beginServing():
        server = await serve_rs(session_generator, None if should_listen_externaly else '127.0.0.1', proxy_port, reuse_address=True)
        await server.serve_forever()

    async def execute():
        async with TaskGroup(wait=any) as group:
            await group.spawn(updateState())
            await group.spawn(beginServing())

        for task in group.tasks:
            if not task.cancelled():
                exc = task.exception()
                if exc:
                    raise exc

    asyncio.run(execute())
