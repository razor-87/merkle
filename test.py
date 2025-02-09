import unittest
from merkle import MerkleProof, gen_leaves, gen_merkle_proof, compute_height, compute_merkle_root


class TestMerkleTree(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.leaves = gen_leaves(1_000)
    cls.root_hash = "d6a21bb2fb85e85ae1363303e29d3ab2b5327ba1b815f1483430e435f294a53b"
    cls.proofs = [
      MerkleProof(
        leaf=b"data item 95",
        position=95,
        hashes=[
          bytes.fromhex("ef20b3d38904a16c1930984009cea34bcad93d930c2654a3372a20259092942f"),
          bytes.fromhex("0630bdb1dcbc6f551eda61cfaa4dfdfa8e7eacdbb2871679e744c776770b6f7a"),
          bytes.fromhex("be24519707850653cca70e39ffe99e44e596d6119a5f4d40cf9b648c42493de7"),
          bytes.fromhex("4885df356b897fd66b2dc1ad62aa6fe280b71ffc65617ad3e620f427d0782bfd"),
          bytes.fromhex("8eabd88f4785b5ea57f79f911149e210587db13054598bbf6c8b6cd887fe57e0"),
          bytes.fromhex("59390e7cd06b43dafec2fde084d0beb5cb90b9374f8823c2ef26cb298cb3925c"),
          bytes.fromhex("dae4f98bb027205a4a58d2c6b89e6252e39f449610134102d85303a3c3aa9287"),
          bytes.fromhex("14fdb8bd2f1777f9df77e94410f33c2a700c727b92ee570bae55ffb0ebe68d1f"),
          bytes.fromhex("93682891149f85226cc818e78fcfc6bf10ef8a54a6094766d309613bdc129591"),
          bytes.fromhex("b2ebcf37f232f62c7af49abad13ca7ede59517990317fe6964c6867631c7a204"),
        ],
      ),
      MerkleProof(
        leaf=b"data item 743",
        position=743,
        hashes=[
          bytes.fromhex("7841d302219dd2e07736bec77ccca89281c636cb4d249d5c97c0475ea26369b5"),
          bytes.fromhex("d6877cf1d85eca1b186c0c3701e1c43655953a2c45d679e592e56959ffc3b889"),
          bytes.fromhex("193b75cf337741273f64a6640cf0d4f2022deeb35e1d618ec5b48021620cbb4f"),
          bytes.fromhex("52ef3926a4902adefd024f3dd013b070c245eac6a0988f2d69fe801547708171"),
          bytes.fromhex("c59451af7760192b422c5bd3f3ab85c54f46054a497e262aaee2668002ae44b0"),
          bytes.fromhex("7923e8b3659c4fd836fa8e412a1cb0cd1527f60c047aa78c3775ad0c52810c44"),
          bytes.fromhex("78c8b299cabd4516448fb9e2c959afb371f72bc9937f45a4a50443fd8e168acb"),
          bytes.fromhex("532c261be943a2d578bd059d55683b9e2028d0cfa0fa6011992e43ae888f37ae"),
          bytes.fromhex("65e4503b298643e2ccdf97ff6cfdb80691fd2d5644ed13b01875714bde43fe84"),
          bytes.fromhex("b70c8523702a428f15d627aaabc24438796284c11de110c77a52065655b60938"),
        ],
      ),
    ]

  def test_gen_merkle_proof(self):
    for proof in self.proofs:
      prob_proof = gen_merkle_proof(self.leaves, len(self.leaves), proof.position)
      self.assertEqual(proof.hashes, prob_proof.hashes, "Merkle proof verification failed.")

  def test_compute_merkle_root(self):
    for proof in self.proofs:
      computed_root = compute_merkle_root(proof)
      self.assertEqual(self.root_hash, computed_root, "Merkle root verification failed.")

  def test_tree_height(self):
    leaves = [b"test1", b"test2", b"test3"]
    height = compute_height(len(leaves))
    self.assertEqual(len(gen_merkle_proof(leaves, len(leaves), 0).hashes), height)


if __name__ == "__main__":
  unittest.main()
