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
	param ([switch]$bcrypt,[switch]$GTX8x1080Ti,[switch]$online,[switch]$raw,$path)
	
	process {
		if ($PSVersionTable.PSEdition -eq "core") {Write-Host "`nCan't run on Powershell Core. Use Windows Powershell instead.`n" -f red; return}
		if (!($online -or $path)) {Write-Host "`nERROR: Missing parameters.`n" -f red; sleep 2; Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name; return}
		
		if ($bcrypt) {
			if ($online) {$doc=((iwr "https://gist.githubusercontent.com/epixoip/9d9b943fd580ff6bfa80e48a0e77520d/raw/b3c5bc087e8d573834ce438e1e8cbe7a2f72007f/bcrypt.md").content).split("`n")}
			elseif ($path) {$doc=gc $path} 
			$res1=$doc | Select-String "hashtype|speed|device" | ConvertFrom-String -Delimiter ":"
			if (!$raw) {$res1} else {$doc}
		}
		if ($GTX8x1080Ti) {
			if ($online) {$doc=((iwr "https://gist.githubusercontent.com/epixoip/ace60d09981be09544fdd35005051505/raw/852687e247a02e05bdbcc57f51fd9604a642bfd0/8x1080Ti.md").content).split("`n")}
			elseif ($path) {$doc=gc $path}
			$res1=($doc).trim(" ") | Select-String "#[1-8]." -NotMatch | Select-String "Hashtype|Speed" | ConvertFrom-String -Delimiter ":"
			if (!$raw) {$res1 | %{$i=0; if ($props) {$props.clear()}}{ $count=$i%(($res1.p1 | select -Unique).count); $props+=@{$($res1.p1 | select -Unique)[$count]=$_.p2}; if ($count -eq (($res1.p1 | select -Unique).count)-1) {New-Object -TypeName PSObject -Property $Props; $props.clear()}; $i++ }}
			else {$doc}
		}
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
			gc passlist.txt | ? {$_} | tpass -HIBP | ? hashtype -match pbkdf2 | sort sectocrack,pass | ft -a
			Test the list of passwords.
		.Example
			$passList | ? {$_} | tpass -HIBP | ? hashtype -match pbkdf2 | sort sectocrack,pass | ft -a
			Test the list of passwords.
	#>
   [CmdletBinding()]
    [Alias("tpass")]
	param (
		[Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)][string]$pass,
		[switch]$HIBP
	)

	begin {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
	
	process {
		if ($PSVersionTable.PSEdition -eq "core") {Write-Host "`nCan't run on Powershell Core. Use Windows Powershell instead.`n" -f red; return}
		if (!$psboundparameters.count) {Get-Help -ex $PSCmdlet.MyInvocation.MyCommand.Name; return}
		if ($HIBP -and !(get-module pscx)) {write-host "`nERROR: HIBP query needs pcsx module from the Gallery: install-module pscx -AllowClobber -confirm:$false.`n" -f red; return}

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
		
		$passSHA1=$hash=($pass | get-hash -Algorithm sha1 -StringEncoding utf8).HashString
		$query=$hash[0..4] -join ""
		if ($HIBP) {
			$result=(Invoke-RestMethod "https://api.pwnedpasswords.com/range/$query").Split("`n") | Select-String $($hash[5..1kb] -join "") | Convertfrom-String -delimiter ":" | select @{n='Hash';e={$_.P1}},@{n='Occurence';e={$_.P2}}
			if ($result) {$passOccurence=$result.Occurence} else {$passOccurence="Not found in HIBP"}
		}
		Get-hashcatBench -GTX8x1080Ti -online | select 'Speed.Dev.#*.....',@{n='Speed';e={if ($_.'Speed.Dev.#*.....' -match "kH/s"){[long]([float](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000)} elseif ($_.'Speed.Dev.#*.....' -match "MH/s"){[long]([float](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000)} elseif ($_.'Speed.Dev.#*.....' -match "GH/s"){[long]([float](($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])*1000000000)} else {(($_.'Speed.Dev.#*.....').trim(" ").split(" ")[0])}}},Hashtype,@{n='Variants';e={$variantsToCrack}} | select Variants,@{n='Speed.Dev';e={$_.'Speed.Dev.#*.....'}},speed,@{n='SecToCrack';e={[math]::round($_.variants/$_.speed,0)}},hashtype,@{n='CountInHIBP';e={$passOccurence}},@{n='Pass';e={$pass}},@{n='PassSHA1';e={$passSHA1}}
	}
}