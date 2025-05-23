rule contains_hello {
    meta:
        description = "contains hello example"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "hello"
    condition:
        $a
}
