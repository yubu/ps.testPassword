function Remove-EmptyLines {
	<#
	.Synopsis
		Remove empty lines from file, string or variable
	.Description
		Remove empty lines from file, string or variable
	.Example
		Remove-EmptyLines -in (gc c:\file.txt)
	.Example
		$var | Remove-EmptyLines
	.Example
        help -ex Remove-EmptyLines | Remove-EmptyLines 
    .Example
        Get-Content *.txt | rmel
    .Example
        Get-ClipBoard | rmel
    .Example
        dir | oss | rmel
    .Example
        dir c:\windows -Recurse | oss | rmel | more
    .Example
        get-help dir | oss | rmel | more
	#>
	[cmdletbinding()]
    [Alias("rmel")]
    param ([parameter(mandatory=$false,position=0,ValueFromPipeline=$true)][array]$in)
    
    begin {$err=""}
    process {
        if (!$psboundparameters.count) {
            help -ex Remove-EmptyLines | out-string | Remove-EmptyLines
            return
        }
        try {$in.split("`r`n") | ? {$_.trim() -ne ""}}
        catch {$err=$_.Exception}
    }
    end {
        if ($err) {Write-Host "ERROR: Use 'out-string -stream' (oss)!" -f red -nonewline; Write-Host "`nExample: dir | oss | rmel. Example: get-help dir | oss | rmel." -f cyan}
    }
}

 function Get-hashcatBench {
<#
	.Synopsis
	   Get hashcat cracking benchmarks: https://gist.github.com/epixoip. System: 8xGTX8x1080Ti - Sagitta Brutalis 1080 Ti (SKU N4X48-GTX1080TI-2620-128-2X500).
	.Description
	   Get hashcat cracking benchmarks: https://gist.github.com/epixoip. System: 8xGTX8x1080Ti - Sagitta Brutalis 1080 Ti (SKU N4X48-GTX1080TI-2620-128-2X500).
	.Example
		Get-hashcatBench -bcrypt 
		Get hashcat cracking benchmarks for bcrypt.
	.Example
		Get-hashcatBench -GTX8x1080Ti -online | ? 'Speed.Dev.#*.....' -like "* h/s"
		Get hashcat cracking benchmarks from Github for 8xGTX1080Ti system, rate is H/s (Hashes/second).
	.Example
		Get-hashcatBench -RTX1x2080S -online | ft -a
		Get hashcat cracking benchmarks from Github for 1 x RTX2080Super FE card with latest hashcat version (Hashcat v5.1.0).
	.Example
		ghcbench -GTX8x1080Ti -path "c:\hashcat-stats\8x1080Ti.md" | ? 'Speed.Dev.#*.....' -like "* mh/s" | sort 'Speed.Dev.#*.....'
		Get hashcat cracking benchmarks from local file, where rate is MH/s (MHashes/second) and sort by speed.
	.Example
		Get-hashcatBench -GTX8x1080Ti -online -raw
		Get file content as is.
	.Example
		ghcbench -GTX8x1080Ti -online | select 'Speed.Dev.#*.....',@{n='Speed';e={if ($_.'Speed.Dev.#*.....' -match "kH/s"){[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000} elseif ($_.'Speed.Dev.#*.....' -match "MH/s"){[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000} elseif ($_.'Speed.Dev.#*.....' -match "GH/s"){[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000000} else {[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])}}},Hashtype | sort speed | ft -a
		Convert table for calculation and sorting.
	.Example
		ghcbench -GTX8x1080Ti -online | select 'Speed.Dev.#*.....',@{n='Speed';e={if ($_.'Speed.Dev.#*.....' -match "kH/s"){[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000} elseif ($_.'Speed.Dev.#*.....' -match "MH/s"){[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000} elseif ($_.'Speed.Dev.#*.....' -match "GH/s"){[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000000} else {[int](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])}}},Hashtype | ? hashtype -match pbkdf | sort Speed | ft -a	
		Search for certain hashtypes.
   #>
   [CmdletBinding()]
    [Alias("ghcbench")]
	param ([switch]$BCrypt,[switch]$GTX8x1080Ti,[switch]$RTX1x2080S,[switch]$Online,[switch]$Raw,$Path)
	
	process {
		if ($PSVersionTable.PSEdition -eq "core") {Write-Host "`nCan't run on Powershell Core. Use Windows Powershell instead.`n" -f red; return}
		if (!($online -or $path)) {Write-Host "`nERROR: Missing parameters.`n" -f red; sleep 2; Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name; return}
		
		if ($bcrypt) {
			if ($online) {$doc=((Invoke-WebRequest -UseBasicParsing "https://gist.githubusercontent.com/epixoip/9d9b943fd580ff6bfa80e48a0e77520d/raw/b3c5bc087e8d573834ce438e1e8cbe7a2f72007f/bcrypt.md").content).split("`n")}
			elseif ($path) {$doc=gc $path} 
			$res1=$doc | Select-String "hashtype|speed|device" | ConvertFrom-String -Delimiter ":"
			if (!$raw) {$res1} else {$doc}
		}
		if ($GTX8x1080Ti) {
			if ($online) {$doc=((Invoke-WebRequest -UseBasicParsing "https://gist.githubusercontent.com/epixoip/ace60d09981be09544fdd35005051505/raw/852687e247a02e05bdbcc57f51fd9604a642bfd0/8x1080Ti.md").content).split("`n")}
			elseif ($path) {$doc=gc $path}
			$res1=($doc).trim(" ") | Select-String "#[1-8]." -NotMatch | Select-String "Hashtype|Speed" | ConvertFrom-String -Delimiter ":"
			if (!$raw) {
				$table=$res1 | %{$i=0; if ($props) {$props.clear()}}{ $count=$i%(($res1.p1 | select -Unique).count); $props+=@{$($res1.p1 | select -Unique)[$count]=$_.p2}; if ($count -eq (($res1.p1 | select -Unique).count)-1) {New-Object -TypeName PSObject -Property $Props; $props.clear()}; $i++ }
				$selectProps=@(
					@{n='SpeedDev';e={[int64]($_.'Speed.Dev.#*.....'.trim() -split " ")[0]}}
					@{n='Rate';e={($_.'Speed.Dev.#*.....'.trim() -split " ")[1]}}
					@{n='Hash';e={($_.hashtype).trim()}}
				)
				$selectProps1=@(
					"SpeedDev"
					"Rate"
					@{n="Speed";e={if ($_.rate -eq  "H/s") {$_.speeddev} elseif ($_.rate -eq  'kH/s') {$_.speeddev*1000} elseif  ($_.rate -eq 'MH/s') {$_.speeddev*1000000} elseif ($_.rate -eq  'GH/s') {$_.speeddev*1000000000}}}
					"hash"
				)
				# @{n="Speed";e={if ($_.rate -eq  "H/s") {$_.speeddev} elseif ($_.rate -eq  'kH/s') {$_.speeddev*1000} elseif  ($_.rate -eq 'MH/s') {$_.speeddev*1000000} elseif ($_.rate -eq  'GH/s') {$_.speeddev*1000000000}}}
				# $table | select @{n='SpeedDev';e={[int64]($_.'Speed.Dev.#*.....'.trim() -split " ")[0]}},Hashtype
				# $table | select -Property $selectProps | select SpeedDev,Rate,@{n="Speed";e={if ($_.rate -eq  "H/s") {$_.speeddev} elseif ($_.rate -eq  'kH/s') {$_.speeddev*1000} elseif  ($_.rate -eq 'MH/s') {$_.speeddev*1000000} elseif ($_.rate -eq  'GH/s') {$_.speeddev*1000000000}}},hash
				$table | select -Property $selectProps | select -Property $selectProps1
			}
			else {$doc}
		}
		if ($RTX1x2080S) {
			if ($online) {$doc=((Invoke-WebRequest -UseBasicParsing "https://gist.github.com/epixoip/47098d25f171ec1808b519615be1b90d/raw/e5837a467cffd2c2a08cf61c0c42ba61f40fe649/2080S.md").content).split("`n")}
			elseif ($path) {$doc=gc $path}
			if (!$raw) {
				
				$hashTemp=new-TemporaryFile
				$doc | sls "hashmode|speed" | ac $hashTemp
				$table=gc $hashTemp -ReadCount 2 | %{[pscustomobject]@{"Speed"=((([string]$_[1]) -split "Speed.#4.........: ")[1]).trim();"Hash"=($_[0] -split(" - "))[1].trim()}}
				del $hashTemp

				$selectProps=@(
					@{n='SpeedDev';e={[int64]($_.speed -split " ")[0]}}
					@{n="Rate";e={($_.speed -split " ")[1]}}
					"Hash"
					@{n="Details";e={($_.speed -split " ")[2..6] -join " "}}
				)
				$selectProps1=@(
					"SpeedDev"
					"Rate"
					@{n="Speed";e={if ($_.rate -eq  "H/s") {$_.speeddev} elseif ($_.rate -eq  'kH/s') {$_.speeddev*1000} elseif  ($_.rate -eq 'MH/s') {$_.speeddev*1000000} elseif ($_.rate -eq  'GH/s') {$_.speeddev*1000000000}}}
					"Hash"
					"Details"
				)
				# $table | select @{n='SpeedDev';e={[int64]($_.speed -split " ")[0]}},@{n="Rate";e={($_.speed -split " ")[1]}},hash,@{n="Desc";e={($_.speed -split " ")[2..6] -join " "}} | select SpeedDev,Rate,@{n="Speed";e={if ($_.rate -eq  "H/s") {$_.speeddev} elseif ($_.rate -eq  'kH/s') {$_.speeddev*1000} elseif  ($_.rate -eq 'MH/s') {$_.speeddev*1000000} elseif ($_.rate -eq  'GH/s') {$_.speeddev*1000000000}}},hash,desc | ft -a
				$table | select -Property $selectProps | select -Property $selectProps1

			}
			else {$doc}
		}
	}
}

function Out-Hash {
	<#
	.Synopsis
	   	Output string hash. Supported hash algorithms: SHA,SHA1,MD5,SHA256,SHA-256,SHA384,SHA-384,SHA512,SHA-512. Supported encoding: UTF8,ASCII,UTF7,UTF32,BigEndianUnicode.
	.Description
	   	Output string hash. Supported hash algorithms: SHA,SHA1,MD5,SHA256,SHA-256,SHA384,SHA-384,SHA512,SHA-512. Supported encoding: UTF8,ASCII,UTF7,UTF32,BigEndianUnicode.
	.Example
		'string1','string2' | Out-Hash -Algorithm SHA256 -Encoding UTF8
		Get hash
	.Example
		(0..20) | %{"string"+(get-random)} | out-hash
		Get hash
	.Example
		gc c:\strings-to-hash.txt | ohash -Algorithm md5
		Get hash
	#>
	[Alias("ohash")]
	param (
		[Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)][string]$in,
		[Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName=$False)][ValidateSet("SHA","SHA1","MD5","SHA256","SHA-256","SHA384","SHA-384","SHA512","SHA-512")][string]$Algorithm="SHA1",
		[Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName=$False)][ValidateSet("UTF8","ASCII","UTF7","UTF32","BigEndianUnicode")][string]$Encoding="UTF8"
	)
	begin {}
	
	process {

		if (!$psboundparameters.count) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name | oss | Remove-EmptyLines; return}
		
		$hash=([System.Security.Cryptography.HashAlgorithm]::Create("$Algorithm").ComputeHash([System.Text.Encoding]::$Encoding.GetBytes("$in")) | % tostring x2).toUpper() -join ""
		write-verbose "`nAlgorithm: $Algorithm Encoding: $encoding"
		$hash
	}
}

function Test-Password {
	<#
		.Synopsis
			Test a password strength, query HIBP DB (https://haveibeenpwned.com/) and print the hashcat benchmarks for various algorithms. System: 8xGTX8x1080Ti - Sagitta Brutalis 1080 Ti (SKU N4X48-GTX1080TI-2620-128-2X500).
		.Description
			Test a password strength, query HIBP DB (https://haveibeenpwned.com/) and print the hashcat benchmarks for various algorithms. System: 8xGTX8x1080Ti - Sagitta Brutalis 1080 Ti (SKU N4X48-GTX1080TI-2620-128-2X500).
		.Example
			Test-Password qwerty | sort SecToCrack | ft -a
			Test the password strength and print the hashcat benchmarks.
		.Example
			Test-Password qwerty -HIBP | sort SecToCrack | ft -a
			Test the password strength, query HIBP DB (https://haveibeenpwned.com/) and print the benchmarks.
		.Example
			Test-Password qwerty -HIBP | ? hashtype -match PBKDF2 | sort SecToCrack | ft -a
			Test the password, query HIBP and get the benchmarks for bcrypt algorithm.
		.Example
			gc passlist.txt | ?{$_} | tpass -HIBP | ? hashtype -match pbkdf2 | sort sectocrack,pass | ft -a
			Test the list of passwords.
		.Example
			$passList | ?{$_} | tpass -HIBP | ? hashtype -match pbkdf2 | sort sectocrack,pass | ft -a
			Test the list of passwords.
		.Example
			Test-Password -HIBPListBreaches | sort BreachDate -desc | ft -a | select -first 10
			Get list of recent breaches from HIBP.
	#>
   [CmdletBinding()]
    [Alias("tpass")]
	param (
		[Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)][string]$pass,
		[Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName=$False,Position=1)][ValidateSet("SHA","SHA1","MD5","SHA256","SHA-256","SHA384","SHA-384","SHA512","SHA-512")][string]$algorithm="SHA1",
		# Default UA for PWS 5.1: 	Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.18362.145
		# Default UA for PWS 6:		Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.18362; en-US) PowerShell/6.2.0 
		# Alternative UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36
		[Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName=$False)][string]$UserAgent,
		[switch]$HIBP,[switch]$noCrackStats,[switch]$HIBPListBreaches,[switch]$HIBPPastes,[switch]$GTX8x1080Ti,[switch]$RTX1x2080S,[switch]$Online,$Path
	)

	begin {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
	
	process {

		if ($PSVersionTable.PSEdition -eq "core") {Write-Host "`nCan't run on Powershell Core. Use Windows Powershell instead.`n" -f red; return}
		if (!$psboundparameters.count) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name; return}

		if ($HIBPListBreaches) {$result=Invoke-RestMethod "https://haveibeenpwned.com/api/v2/breaches" -UserAgent $UserAgent; $result; return}
		
		$passComplexity=0
		$lowerCaseComplexity=26
		$upperCaseComplexity=26
		$numbersComplexity=10
		$nonAlphaNumComplexity=33
		
		Write-Host "`nPassword: $pass"
		if (($pass).Length -le 11) {Write-Host "BAD! Password length is only $(($pass).Length) characters. Longer is better. Start from 12" -f red} else {Write-Host "OK. Password length: $(($pass).Length)" -f green}
		if ($lowerCaseCount=("$pass"[0..1kb] -cmatch "[a-z]").count) {$passComplexity=$lowerCaseComplexity; Write-Host "OK. Lower case: $lowerCaseCount" -f Green} else {Write-Host "BAD! No Lower case" -f Red}
		if ($upperCaseCount=("$pass"[0..1kb] -cmatch "[A-Z]").count) {$passComplexity+=$upperCaseComplexity; Write-Host "OK. Upper case: $upperCaseCount" -f Green} else {Write-Host "BAD! No Upper case" -f Red}
		if ($numbersCount=("$pass"[0..1kb] -cmatch "[0-9]").count) {$passComplexity+=$numbersComplexity; Write-Host "OK. Numbers: $numbersCount" -f Green} else {Write-Host "BAD! No Numbers" -f Red}
		if ($nonAlphaNumCount=("$pass"[0..1kb] -match "[^a-zA-Z0-9]").count) {$passComplexity+=$nonAlphaNumComplexity; Write-Host "OK. NonAlphaNum: $nonAlphaNumCount" -f Green} else {Write-Host "BAD! No NonAlphaNumeric" -f Red}
		
		$variantsToCrack=[math]::pow($passComplexity,(($pass).Length))
		
		Write-Host "Total password complexity: " -NoNewline
		Write-Host "$passComplexity" -f Yellow
		Write-Host "Total password variants to brute force: " -NoNewline
		Write-Host "$variantsToCrack" -f Yellow
		
		$passSHA1=$hash=$pass | out-hash

		$query=$hash[0..4] -join ""
		if ($HIBP) {
			$result=(Invoke-RestMethod "https://api.pwnedpasswords.com/range/$query" -UserAgent "$UserAgent").Split("`n") | Select-String $($hash[5..1kb] -join "") | ConvertFrom-String -delimiter ":" | select @{n='Hash';e={$_.P1}},@{n='Occurrence';e={$_.P2}}
			if ($result) {$passOccurrence=$result.Occurrence} else {$passOccurrence="Not found in HIBP"}
			if ($noCrackStats) {
				if ($passOccurrence -eq "Not found in HIBP") {write-host "`nHIBP: $passOccurrence `n" -f green} else {Write-host "`nHIBP: password occurrences: $passOccurrence`n" -f red}
				return
			}
		}
		if (!$noCrackStats)	{
			# Get-hashcatBench -GTX8x1080Ti -online | select 'Speed.Dev.#*.....',@{n='Speed';e={if ($_.'Speed.Dev.#*.....' -match "kH/s"){[long]([float](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000)} elseif ($_.'Speed.Dev.#*.....' -match "MH/s"){[long]([float](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000)} elseif ($_.'Speed.Dev.#*.....' -match "GH/s"){[long]([float](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000000)} else {(($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])}}},Hashtype,@{n='Variants';e={$variantsToCrack}} | select Variants,@{n='Speed.Dev';e={$_.'Speed.Dev.#*.....'}},speed,@{n='SecToCrack';e={[math]::round($_.variants/$_.speed,0)}},hashtype,@{n='CountInHIBP';e={$passOccurrence}},@{n='Pass';e={$pass}},@{n='PassSHA1';e={$passSHA1}}
			$selectProps=@(
				@{n='Variants';e={$variantsToCrack}}
				"SpeedDev"
				"Rate"
				"Speed"
				# @{n='SecToCrack';e={[math]::round($_.variants/$_.speed,0)}}	
				"Hash"
				@{n='CountInHIBP';e={$passOccurrence}}
				@{n='Pass';e={$pass}}
				@{n='PassSHA1';e={$passSHA1}}			
			)
			if ($GTX8x1080Ti) {Get-hashcatBench -GTX8x1080Ti -online | select -Property $selectProps | select Variants,SpeedDev,Rate,Speed,@{n='SecToCrack';e={[math]::round($_.variants/$_.speed,0)}},Hash,CountInHIBP,Pass,PassSHA1}
			elseif ($RTX1x2080S) {Get-hashcatBench -RTX1x2080S -online | select -Property $selectProps | select Variants,SpeedDev,Rate,Speed,@{n='SecToCrack';e={[math]::round($_.variants/$_.speed,0)}},Hash,CountInHIBP,Pass,PassSHA1}
			else {Get-hashcatBench -RTX1x2080S -online | select -Property $selectProps | select Variants,SpeedDev,Rate,Speed,@{n='SecToCrack';e={[math]::round($_.variants/$_.speed,0)}},Hash,CountInHIBP,Pass,PassSHA1}
		}
	}
}
