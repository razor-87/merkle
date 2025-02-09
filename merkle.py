import hashlib
import math
import time
from dataclasses import dataclass
from random import randint
from typing import NamedTuple

Tree = NamedTuple("Tree", [("num_leaves", int), ("root_hash", str)])
TREES = [
  Tree(100, "95b882a4c3bc97ff001e447e9b60b6a97f08e2daf15bdb5d42dfff733748c061"),
  Tree(1_000, "d6a21bb2fb85e85ae1363303e29d3ab2b5327ba1b815f1483430e435f294a53b"),
  Tree(10_000, "158f34804e0558f7295ac414a4658e12a1605025ff82f5338b7f046295f865a9"),
  Tree(100_000, "ea4f9fd75feccfd05f50f6da2b30360bf198c0adb6fbcbe77083e815c6dc5481"),
  Tree(1_000_000, "eaec013bcbd90a05957492a98c997aee5f0ea0b0b612bd3782538af710d82c65"),
]

DEBUG = True


def run():
  for tree in TREES:
    rnd_position = randint(0, tree.num_leaves - 1)

    st = time.perf_counter_ns()
    leaves = gen_leaves(tree.num_leaves)
    et = time.perf_counter_ns()
    print(f"Generated {tree.num_leaves} leaves for a Merkle tree. {{ elapsed time: {(et - st) * 1e-6:.3f} ms }}")

    st = time.perf_counter_ns()
    proof = gen_merkle_proof(leaves, tree.num_leaves, rnd_position)
    et = time.perf_counter_ns()
    print(f"Generated a Merkle proof for leaf #{proof.position}. {{ elapsed time: {(et - st) * 1e-6:.3f} ms }}")

    st = time.perf_counter_ns()
    computed_root = compute_merkle_root(proof)
    et = time.perf_counter_ns()
    print(f"Computed a root hash from proof. {{ elapsed time: {(et - st) * 1e-6:.3f} ms }}")

    print(
      f"  Leaf {{ position: {proof.position}, value: '{proof.leaf.decode()}', hash: {hash_leaf(proof.leaf).hex()} }}"
    )
    if DEBUG:
      assert tree.root_hash == computed_root, ("Verify failed!", computed_root, tree.root_hash)
      pprint(proof.hashes)


@dataclass
class MerkleProof:
  leaf: bytes
  position: int
  hashes: list[bytes]  # path


def gen_leaves(num_leaves: int) -> list[bytes]:
  return [f"data item {i}".encode() for i in range(num_leaves)]


def hash_leaf(leaf: bytes) -> bytes:
  sha256 = hashlib.sha256()
  sha256.update(b"leaf:")
  sha256.update(leaf)
  return sha256.digest()


def hash_internal_node(left: bytes, right: bytes) -> bytes:
  sha256 = hashlib.sha256()
  sha256.update(b"node:")
  sha256.update(left)
  sha256.update(right)
  return sha256.digest()


def compute_merkle_root(proof: MerkleProof) -> str:
  rh = hash_leaf(proof.leaf)
  level_pos = proof.position
  for sh in proof.hashes:
    rh = hash_internal_node(*((sh, rh) if level_pos & 1 else (rh, sh)))
    level_pos >>= 1
  return rh.hex()


def pprint(hashes: list[bytes]) -> None:
  print(f"  Hash values:\n{'\n'.join(f'    {i}:{hv.hex()}' for i, hv in enumerate(hashes))}")


def compute_height(num_leaves: int) -> int:
  return math.ceil(math.log2(num_leaves))


def gen_merkle_proof(leaves: list[bytes], num_leaves: int, pos: int) -> MerkleProof:
  state = [hash_leaf(leaf) for leaf in leaves]
  height_tree = compute_height(num_leaves)
  padlen = (1 << height_tree) - num_leaves
  state.extend([b"\x00"] * padlen)
  level_pos, hashes = pos, []
  for _ in range(height_tree):
    sibling = state[level_pos - 1] if level_pos & 1 else state[level_pos + 1]
    hashes.append(sibling)
    state = [hash_internal_node(state[i], state[i + 1]) for i in range(0, len(state), 2)]
    level_pos >>= 1
  return MerkleProof(leaves[pos], pos, hashes)


if __name__ == "__main__":
  run()
