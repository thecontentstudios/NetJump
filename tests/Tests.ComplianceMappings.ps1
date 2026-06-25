# Pester 5 tests for src/86-compliance-mappings.ps1

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    # The compliance module references $script:AttackMap from the main file. Build a minimal
    # synthetic AttackMap so the integrity assertions have something to validate against.
    $script:AttackMap = @{
        'persist-run'    = @{ Id = 'T1547.001'; Name = 'Run keys'      }
        'byovd'          = @{ Id = 'T1068';     Name = 'BYOVD'         }
        'beaconing'      = @{ Id = 'T1071';     Name = 'Beaconing'     }
        'threat-intel'   = @{ Id = 'T1071';     Name = 'TI match'      }
        'defender-off'   = @{ Id = 'T1562.001'; Name = 'Defender off'  }
        'posture-smb1'   = @{ Id = 'T1210';     Name = 'SMBv1'         }
        'posture-llmnr'  = @{ Id = 'T1557.001'; Name = 'LLMNR/NBT-NS'  }
        'posture-wdigest'= @{ Id = 'T1003.001'; Name = 'WDigest'       }
        'arp-spoof'      = @{ Id = 'T1557.002'; Name = 'ARP spoofing'  }
        'driver-bsod'    = @{ Id = 'T1014';     Name = 'Rootkit'       }
        'hosts-tamper'   = @{ Id = 'T1565.001'; Name = 'Hosts tamper'  }
        'proxy-hijack'   = @{ Id = 'T1090';     Name = 'Proxy'         }
        'dns-suspicious' = @{ Id = 'T1071.004'; Name = 'DNS C2'        }
        'dns-dga'        = @{ Id = 'T1568.002'; Name = 'DGA'           }
        'doh-evasion'    = @{ Id = 'T1071.004'; Name = 'DoH'           }
        'c2-dns'         = @{ Id = 'T1071.004'; Name = 'C2 DNS'        }
        'c2-suspicious'  = @{ Id = 'T1071';     Name = 'C2 suspect'    }
        'dll-hijack'     = @{ Id = 'T1574.001'; Name = 'DLL hijack'    }
        'unsigned-temp'  = @{ Id = 'T1036';     Name = 'Masquerade'    }
        'unsigned-extern'= @{ Id = 'T1071';     Name = 'C2 unsigned'   }
        'persist-startup'= @{ Id = 'T1547.001'; Name = 'Startup folder'}
        'persist-service'= @{ Id = 'T1543.003'; Name = 'Service'       }
        'persist-task'   = @{ Id = 'T1053.005'; Name = 'Scheduled task'}
        'persist-wmi'    = @{ Id = 'T1546.003'; Name = 'WMI'           }
    }
    . (Join-Path $repoRoot 'src\86-compliance-mappings.ps1')
}

Describe 'NIST CSF 2.0 framework matrix integrity' {
    It 'has every required field on every entry' {
        foreach ($group in $script:NistCsfFramework.Keys) {
            foreach ($it in $script:NistCsfFramework[$group]) {
                $it.Id    | Should -Not -BeNullOrEmpty
                $it.Name  | Should -Not -BeNullOrEmpty
                $it.Rules | Should -Not -Be $null   # array can be empty but must exist
            }
        }
    }

    It 'every rule key referenced by the matrix exists in $script:AttackMap' {
        $unknown = @()
        foreach ($group in $script:NistCsfFramework.Keys) {
            foreach ($it in $script:NistCsfFramework[$group]) {
                foreach ($r in $it.Rules) {
                    if (-not $script:AttackMap.ContainsKey($r)) { $unknown += "$($it.Id) -> $r" }
                }
            }
        }
        $unknown | Should -BeNullOrEmpty -Because "Every rule key in NIST CSF must exist in AttackMap. Unknown: $($unknown -join ', ')"
    }

    It 'includes all 6 NIST CSF 2.0 functions' {
        $expected = @('GV (Govern)', 'ID (Identify)', 'PR (Protect)', 'DE (Detect)', 'RS (Respond)', 'RC (Recover)')
        foreach ($e in $expected) { $script:NistCsfFramework.Keys | Should -Contain $e }
    }
}

Describe 'CIS Controls v8 framework matrix integrity' {
    It 'has every required field on every entry' {
        foreach ($group in $script:CisControlsFramework.Keys) {
            foreach ($it in $script:CisControlsFramework[$group]) {
                $it.Id    | Should -Not -BeNullOrEmpty
                $it.Name  | Should -Not -BeNullOrEmpty
                $it.Rules | Should -Not -Be $null
            }
        }
    }

    It 'every rule key referenced by the matrix exists in $script:AttackMap' {
        $unknown = @()
        foreach ($group in $script:CisControlsFramework.Keys) {
            foreach ($it in $script:CisControlsFramework[$group]) {
                foreach ($r in $it.Rules) {
                    if (-not $script:AttackMap.ContainsKey($r)) { $unknown += "$($it.Id) -> $r" }
                }
            }
        }
        $unknown | Should -BeNullOrEmpty -Because "Every rule key in CIS Controls must exist in AttackMap. Unknown: $($unknown -join ', ')"
    }
}
