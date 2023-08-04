spicy_add_analyzer(
    NAME GOOSE
    PACKAGE_NAME GOOSE
    SOURCES goose.spicy goose.evt zeek_goose.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
