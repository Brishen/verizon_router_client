from verizon_router_client.cr1000a import arc_md5, luci_password, luci_username

ARC_ADMIN = (
    "edbd881f1ee2f76ba0bd70fd184f87711be991a0401fd07ccd4b199665f00761"
    "afc91731d8d8ba6cbb188b2ed5bfb465b9f3d30231eb0430b9f90fe91d136648"
)
ARC_HUNTER2 = (
    "71a8a7c1fcdbb6de4f7de52ea71fe5f883d83e553cd22464042c35a69fea31a4"
    "79d3898f8bbcdf58774587b4e9de8e157598dcaf3fa3ff7fa630da8b0f3bad47"
)
LUCI_HUNTER2_TOKEN_A32 = (
    "777fb735b42c11ad40e814f3ff9f8321c4dd27250ed9c00c847343a29601d248"
    "f248cb4c878cdc96a1128ac9610febb73911ca9e177b8bd32e11ffed90d89156"
)


def test_arc_md5_known_vectors():
    assert arc_md5("admin") == ARC_ADMIN
    assert arc_md5("hunter2") == ARC_HUNTER2


def test_arc_md5_handles_non_ascii():
    # JS path masks char codes to 8 bits; must not raise.
    digest = arc_md5("pässwörd☃")
    assert len(digest) == 128
    assert digest == arc_md5("pässwörd☃")


def test_luci_username_is_arc_md5():
    assert luci_username("admin") == ARC_ADMIN


def test_luci_password_without_token_is_arc_md5():
    assert luci_password("hunter2", "") == ARC_HUNTER2


def test_luci_password_with_token():
    assert luci_password("hunter2", "a" * 32) == LUCI_HUNTER2_TOKEN_A32
    assert luci_password("hunter2", "b" * 32) != LUCI_HUNTER2_TOKEN_A32
