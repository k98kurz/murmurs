from context import pie
import unittest


class TestPIEFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._functions = {**pie._functions}
        return super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        pie._functions = cls._functions
        return super().tearDownClass()

    def test_set_sign_function(self):
        func = lambda b1, b2: b1+b2
        assert pie._functions['sign'] is not func
        pie.set_sign_function(func)
        assert pie._functions['sign'] is func

    def test_set_checksig_function(self):
        func = lambda b1, b2, b3: b1==b2==b3
        assert pie._functions['check_sig'] is not func
        pie.set_checksig_function(func)
        assert pie._functions['check_sig'] is func

    def test_set_elect_root_func(self):
        func = lambda b1, b2, i: len(b1) == len(b2) == i
        assert pie._functions['elect_root'] is not func
        pie.set_elect_root_func(func)
        assert pie._functions['elect_root'] is func

    def test_set_send_message_func(self):
        func = lambda pm: pm
        assert pie._functions['send_message'] is not func
        pie.set_send_message_func(func)
        assert pie._functions['send_message'] is func

    def test_signed_int_to_bytes(self):
        b1 = pie.signed_int_to_bytes(11)
        b2 = pie.signed_int_to_bytes(-11)
        b3 = pie.signed_int_to_bytes(1000)

        assert type(b1) is type(b2) is type(b3) is bytes
        assert len(b1) == len(b2) == 1
        assert b1 != b2
        assert len(b3) == 2

    def test_int_to_2_bytes(self):
        b1 = pie.int_to_2_bytes(11)
        b2 = pie.int_to_2_bytes(-11)
        b3 = pie.int_to_2_bytes(1000)

        assert type(b1) is type(b2) is type(b3) is bytes
        assert len(b1) == len(b2) == len(b3) == 2
        assert b1 != b2
        assert b1 != b3
        assert b2 != b3

    def test_bytes_to_int(self):
        i1 = pie.bytes_to_int(b'\xff\x00')
        i2 = pie.bytes_to_int(b'\xff\xff')
        i3 = pie.bytes_to_int(b'\x10\x00\x00')

        assert type(i1) is type(i2) is type(i3) is int
        assert i1 != i2
        assert i1 != i3
        assert i2 != i3

    def test_bytes_int_conversions_e2e(self):
        ints = list(range(300))
        bts = []
        for i in ints:
            bts.append(pie.int_to_2_bytes(i))

        decoded = [pie.bytes_to_int(b) for b in bts]
        assert decoded == ints

    def test_encode_coordinates_and_decode_coordinates_e2e(self):
        coords = [5, -4, -3, 2, -2, 1]
        encoded = pie.encode_coordinates(coords)
        assert type(encoded) is bytes
        assert len(encoded) == len(coords) * 2
        decoded = pie.decode_coordinates(encoded)
        assert type(decoded) is list
        assert all(type(d) is int for d in decoded)
        assert decoded == coords

    def test_encode_big_coordinates_and_decode_big_coordinates_e2e(self):
        coords1 = [555555, -444, -3, 2, -2, 1]
        coords2 = [5, -4, -3, 2, -2, 1]
        encoded = pie.encode_big_coordinates(coords1)
        assert type(encoded) is bytes
        decoded = pie.decode_big_coordinates(encoded)
        assert type(decoded) is list
        assert all(type(d) is int for d in decoded)
        assert decoded == coords1
        encoded2 = pie.encode_big_coordinates(coords2)
        assert len(encoded) != len(encoded2)
        assert pie.decode_big_coordinates(encoded2) == coords2


if __name__ == '__main__':
    unittest.main()
