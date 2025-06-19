import pytest


@pytest.mark.qemu
def test_esp_encrypted_img(dut) -> None:
    dut.run_all_single_board_cases()


@pytest.mark.generic
def test_esp_encrypted_img_generic(dut) -> None:
    dut.run_all_single_board_cases()
