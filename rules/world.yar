 rule contains_world {
    meta:
        description = "contains world example"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "world"
    condition:
        $a
}
