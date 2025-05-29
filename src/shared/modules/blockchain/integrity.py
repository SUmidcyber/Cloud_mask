from hashlib import sha256
import json
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import pytz

@dataclass
class BlockHeader:
    version: str = "1.0"
    timestamp: str = ""
    previous_hash: str = ""
    merkle_root: str = ""
    nonce: int = 0
    difficulty: int = 4

@dataclass
class SecurityLog:
    timestamp: str
    source: str
    event_type: str
    details: Dict
    signature: Optional[str] = None

class SecurityBlockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Dict] = []
        self.pending_logs: List[SecurityLog] = []
        self.difficulty = difficulty
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_header = BlockHeader(
            timestamp=str(datetime.now(pytz.utc)),
            previous_hash="0"*64,
            difficulty=self.difficulty
        )
        genesis_block = {
            "header": asdict(genesis_header),
            "logs": [],
            "hash": self.calculate_hash(genesis_header, [])
        }
        self.chain.append(genesis_block)

    def add_log(self, log: SecurityLog):
        """Add a new security log to pending logs"""
        if not log.timestamp:
            log.timestamp = str(datetime.now(pytz.utc))
        self.pending_logs.append(log)

    def mine_block(self) -> Optional[Dict]:
        if not self.pending_logs:
            return None

        last_block = self.chain[-1]
        new_header = BlockHeader(
            timestamp=str(datetime.now(pytz.utc)),
            previous_hash=last_block["hash"],
            difficulty=self.difficulty
        )

        # Calculate Merkle root
        log_hashes = [self.hash_log(log) for log in self.pending_logs]
        merkle_root = self.calculate_merkle_root(log_hashes)

        new_header.merkle_root = merkle_root
        block_hash, nonce = self.proof_of_work(new_header)

        new_block = {
            "header": {**asdict(new_header), "nonce": nonce},
            "logs": [asdict(log) for log in self.pending_logs],
            "hash": block_hash
        }

        self.chain.append(new_block)
        self.pending_logs = []
        return new_block

    def proof_of_work(self, header: BlockHeader) -> Tuple[str, int]:
        current_nonce = 0
        while True:
            header.nonce = current_nonce
            header_dict = asdict(header)
            block_hash = self.calculate_hash(header_dict, [])
            if block_hash.startswith("0" * self.difficulty):
                return block_hash, current_nonce
            current_nonce += 1

    @staticmethod
    def calculate_hash(header: Dict, logs: List) -> str:
        block_string = json.dumps(header, sort_keys=True) + json.dumps(logs, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

    @staticmethod
    def hash_log(log: SecurityLog) -> str:
        log_dict = asdict(log)
        return sha256(json.dumps(log_dict, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def calculate_merkle_root(hashes: List[str]) -> str:
        if not hashes:
            return ""
        
        while len(hashes) > 1:
            new_hashes = []
            for i in range(0, len(hashes), 2):
                if i + 1 == len(hashes):
                    combined = hashes[i] + hashes[i]
                else:
                    combined = hashes[i] + hashes[i+1]
                new_hashes.append(sha256(combined.encode()).hexdigest())
            hashes = new_hashes
        return hashes[0]