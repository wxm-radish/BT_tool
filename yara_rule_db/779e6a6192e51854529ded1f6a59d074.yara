rule checkfunc {
meta:
    autor = "radish"
    func_name = "net_http___Client__Get"
    go_version = "GO-1.16"
    go_arch = "Linux"
strings:
    $s1 = {64488b0c25f8ffffff483b61100f86dc0000004883ec6048896c2458488d6c2458488b05b01a2700488D0D [4] 48890c244889442408488D05 [4] 488944241048c744241803000000488b4424704889442420488b44247848894424280f57c00f11442430E8 [4] 488b442448488b4c2450488b54244048837c244800742648c784248000000000000000488984248800000048898c2490000000488b6c24584883c460c3488b442468488904244889542408E8 [4] 488b442418488b4c2420488b5424104889942480000000488984248800000048898c2490000000488b6c24584883c460c3E8}
condition:
    any of them
}