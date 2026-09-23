#Requires -Version 7.0
# ============================================================
# AUDITORÍA OSINT - PORTALES MUNICIPALES DE TLAXCALA
# ============================================================
#
# Requisitos:
#   PowerShell 7+ (Windows, Linux o macOS)
#   - En Windows se usa Resolve-DnsName.
#   - En Linux/macOS se usa "dig" si está instalado; si no,
#     solo se obtienen registros A/AAAA (CNAME/NS quedan N/D).
#
# El script realiza comprobaciones PASIVAS:
#   - DNS
#   - HTTP / HTTPS
#   - Cabeceras HTTP
#   - Cookies
#   - TLS / certificado
#   - Tiempos de respuesta
#   - Tecnologías (cabeceras, cookies y HTML de la portada)
#   - ASN / proveedor de la IP (DNS de Team Cymru) y DNS inverso
#
# NO realiza:
#   - explotación
#   - fuzzing
#   - escaneo de puertos
#   - fuerza bruta
#   - pruebas de vulnerabilidad
#
# Si una comprobación falla, registra el error y continúa.
#
# Uso:
#   pwsh -File .\auditoria.ps1
#   pwsh -File .\auditoria.ps1 -SoloDominios apizaco.gob.mx,tlaxco.gob.mx
# ============================================================

param(
    # Opcional: auditar solo estos dominios de la lista.
    [string[]]$SoloDominios
)

# ------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------

$OutputDir = Join-Path $PSScriptRoot "auditoria-tlaxcala"

$ResultsFile = Join-Path $OutputDir "auditoria_resultados.csv"
$ErrorsFile  = Join-Path $OutputDir "auditoria_errores.csv"

$TimeoutSeconds = 20
$MaxRedirects   = 5
$CertWarnDays   = 30

$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
             "AppleWebKit/537.36 (KHTML, like Gecko) " +
             "Chrome/140 Safari/537.36 " +
             "Municipal-OSINT-Audit/1.0"

# ------------------------------------------------------------
# CREAR DIRECTORIO
# ------------------------------------------------------------

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# ------------------------------------------------------------
# LISTA DE MUNICIPIOS
# ------------------------------------------------------------

$Sites = @(
    @{ Municipio="Acuamanala de Miguel Hidalgo"; Dominio="acuamanala.gob.mx" },
    @{ Municipio="Amaxac de Guerrero"; Dominio="amaxac.gob.mx" },
    @{ Municipio="Apetatitlán de Antonio Carvajal"; Dominio="apetatitlan-tlax.gob.mx" },
    @{ Municipio="Apizaco"; Dominio="apizaco.gob.mx" },
    @{ Municipio="Atlangatepec"; Dominio="atlangatepec.gob.mx" },
    @{ Municipio="Atltzayanca"; Dominio="atltzayanca.gob.mx" },
    @{ Municipio="Benito Juárez"; Dominio="bjuareztlax.gob.mx" },
    @{ Municipio="Calpulalpan"; Dominio="calpulalpan.gob.mx" },
    @{ Municipio="Chiautempan"; Dominio="chiautempan.gob.mx" },
    @{ Municipio="Contla de Juan Cuamatzi"; Dominio="contla.gob.mx" },
    @{ Municipio="Cuapiaxtla"; Dominio="ayuntamientocuapiaxtla.org" },
    @{ Municipio="Cuaxomulco"; Dominio="cuaxomulcotlax.gob.mx" },
    @{ Municipio="El Carmen Tequexquitla"; Dominio="elcarmentequexquitla.gob.mx" },
    @{ Municipio="Emiliano Zapata"; Dominio="zapata.gob.mx" },
    @{ Municipio="Españita"; Dominio="espanitatlax.gob.mx" },
    @{ Municipio="Huamantla"; Dominio="huamantla.gob.mx" },
    @{ Municipio="Hueyotlipan"; Dominio="hueyotlipan.gob.mx" },
    @{ Municipio="Ixtacuixtla de Mariano Matamoros"; Dominio="ixtacuixtla.gob.mx" },
    @{ Municipio="Ixtenco"; Dominio="ixtenco.gob.mx" },
    @{ Municipio="La Magdalena Tlaltelulco"; Dominio="tlaltelulco.gob.mx" },
    @{ Municipio="Lázaro Cárdenas"; Dominio="lazarocardenastlax.gob.mx" },
    @{ Municipio="Mazatecochco de José María Morelos"; Dominio="mazatecochco.gob.mx" },
    @{ Municipio="Muñoz de Domingo Arenas"; Dominio="munoz.gob.mx" },
    @{ Municipio="Nanacamilpa de Mariano Arista"; Dominio="nanacamilpa.gob.mx" },
    @{ Municipio="Natívitas"; Dominio="nativitastlax.gob.mx" },
    @{ Municipio="Panotla"; Dominio="ayuntamientopanotla.gob.mx" },
    @{ Municipio="Papalotla de Xicohténcatl"; Dominio="papalotlatlaxcala.gob.mx" },
    @{ Municipio="San Damián Texóloc"; Dominio="texoloctlax.gob.mx" },
    @{ Municipio="San Francisco Tetlanohcan"; Dominio="tetlanohcan.gob.mx" },
    @{ Municipio="San Jerónimo Zacualpan"; Dominio="ayuntamientozacualpan.mx" },
    @{ Municipio="San José Teacalco"; Dominio="sanjoseteacalco.gob.mx" },
    @{ Municipio="San Juan Huactzinco"; Dominio="huactzinco.gob.mx" },
    @{ Municipio="San Lorenzo Axocomanitla"; Dominio="axocomanitla.gob.mx" },
    @{ Municipio="San Lucas Tecopilco"; Dominio="tecopilco.gob.mx" },
    @{ Municipio="San Pablo del Monte"; Dominio="ayuntamientospm.gob.mx" },
    @{ Municipio="Sanctórum de Lázaro Cárdenas"; Dominio="sanctorum.gob.mx" },
    @{ Municipio="Santa Ana Nopalucan"; Dominio="nopalucan.gob.mx" },
    @{ Municipio="Santa Apolonia Teacalco"; Dominio="teacalco.gob.mx" },
    @{ Municipio="Santa Catarina Ayometla"; Dominio="ayometla.gob.mx" },
    @{ Municipio="Santa Cruz Quilehtla"; Dominio="quilehtlatlax.gob.mx" },
    @{ Municipio="Santa Cruz Tlaxcala"; Dominio="santacruz-tlaxcala.gob.mx" },
    @{ Municipio="Santa Isabel Xiloxoxtla"; Dominio="xiloxoxtla.gob.mx" },
    @{ Municipio="Tenancingo"; Dominio="tenancingo.gob.mx" },
    @{ Municipio="Teolocholco"; Dominio="teolocholco.gob.mx" },
    @{ Municipio="Tepetitla de Lardizábal"; Dominio="tepetitladelardizbal.com" },
    @{ Municipio="Tepeyanco"; Dominio="tepeyanco.gob.mx" },
    @{ Municipio="Terrenate"; Dominio="terrenate-terrenate.gob.mx" },
    @{ Municipio="Tetla de la Solidaridad"; Dominio="tetladelasolidaridad.gob.mx" },
    @{ Municipio="Tetlatlahuca"; Dominio="tetlatlahuca.gob.mx" },
    @{ Municipio="Tlaxcala de Xicohténcatl"; Dominio="tlaxcaladexicohtencatl.gob.mx" },
    @{ Municipio="Tlaxco"; Dominio="tlaxco.gob.mx" },
    @{ Municipio="Tocatlán"; Dominio="tocatlantlaxcala.gob.mx" },
    @{ Municipio="Totolac"; Dominio="totolac.gob.mx" },
    @{ Municipio="Tzompantepec"; Dominio="tzompantepectlax.gob.mx" },
    @{ Municipio="Xaloztoc"; Dominio="xaloztoc.gob.mx" },
    @{ Municipio="Xaltocan"; Dominio="xaltocan.gob.mx" },
    @{ Municipio="Xicohtzinco"; Dominio="xicohtzinco.gob.mx" },
    @{ Municipio="Yauhquemehcan"; Dominio="yauhquemehcantlax.gob.mx" },
    @{ Municipio="Zacatelco"; Dominio="zacatelco.gob.mx" },
    @{ Municipio="Zitlaltepec de Trinidad Sánchez Santos"; Dominio="zitlaltepec.gob.mx" }
)

if ($SoloDominios) {
    $Sites = @($Sites | Where-Object { $SoloDominios -contains $_.Dominio })
}

# ------------------------------------------------------------
# FUNCIONES AUXILIARES
# ------------------------------------------------------------

$Errors  = New-Object System.Collections.Generic.List[object]
$Results = New-Object System.Collections.Generic.List[object]

$HasResolveDnsName = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
$HasDig            = [bool](Get-Command dig -ErrorAction SilentlyContinue)

function Add-AuditError {
    param(
        [string]$Municipio,
        [string]$Dominio,
        [string]$Categoria,
        [string]$ErrorMessage
    )

    $Errors.Add([PSCustomObject]@{
        Fecha      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Municipio  = $Municipio
        Dominio    = $Dominio
        Categoria  = $Categoria
        Error      = $ErrorMessage
    })
}

# Devuelve el mensaje de la excepción más interna
# (evita "One or more errors occurred." de AggregateException).
function Get-ErrorMessage {
    param($ErrorRecord)

    $Exception = $ErrorRecord

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $Exception = $ErrorRecord.Exception
    }

    if ($Exception -is [System.Exception]) {
        $Base = $Exception.GetBaseException()

        if ($Base -is [System.TimeoutException] -or
            $Exception -is [System.Threading.Tasks.TaskCanceledException]) {
            return "Timeout ($TimeoutSeconds s): $($Base.Message)"
        }

        return $Base.Message
    }

    return [string]$ErrorRecord
}

# Obtiene una cabecera de un HttpResponseMessage
# (cabeceras de respuesta y de contenido).
function Get-HeaderValue {
    param(
        [System.Net.Http.HttpResponseMessage]$Response,
        [string]$Name
    )

    if ($null -eq $Response) { return $null }

    $Values = $null

    if ($Response.Headers.TryGetValues($Name, [ref]$Values)) {
        return (@($Values) -join "; ")
    }

    if ($null -ne $Response.Content -and
        $Response.Content.Headers.TryGetValues($Name, [ref]$Values)) {
        return (@($Values) -join "; ")
    }

    return $null
}

# Resolución DNS multiplataforma.
function Resolve-AuditDns {
    param(
        [string]$Name,
        [ValidateSet("A", "AAAA", "CNAME", "NS")]
        [string]$Type
    )

    if ($HasResolveDnsName) {

        $Records = Resolve-DnsName `
            -Name $Name `
            -Type $Type `
            -DnsOnly `
            -ErrorAction Stop

        $Filtered = @($Records | Where-Object { $_.Type -eq $Type })

        switch ($Type) {
            { $_ -in "A", "AAAA" } { return @($Filtered | Select-Object -ExpandProperty IPAddress) }
            default                { return @($Filtered | Select-Object -ExpandProperty NameHost) }
        }
    }

    if ($HasDig) {

        $Output = & dig +short +time=5 +tries=2 $Name $Type 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "dig terminó con código $LASTEXITCODE`: $($Output -join ' ')"
        }

        $Lines = @($Output | ForEach-Object { "$_".Trim() } | Where-Object { $_ })

        # dig +short mezcla CNAME intermedios con A/AAAA; filtramos por formato.
        switch ($Type) {
            "A"     { return @($Lines | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) }
            "AAAA"  { return @($Lines | Where-Object { $_ -match '^[0-9a-fA-F:]+$' -and $_ -match ':' }) }
            default { return @($Lines | ForEach-Object { $_.TrimEnd('.') }) }
        }
    }

    # Último recurso: .NET solo resuelve direcciones.
    switch ($Type) {
        "A" {
            return @([System.Net.Dns]::GetHostAddresses($Name) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.ToString() })
        }
        "AAAA" {
            return @([System.Net.Dns]::GetHostAddresses($Name) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } |
                ForEach-Object { $_.ToString() })
        }
        default {
            throw "N/D: consulta $Type requiere Resolve-DnsName (Windows) o dig."
        }
    }
}

# Cliente HTTP reutilizable.
function New-AuditHttpClient {
    param([bool]$FollowRedirects)

    $Handler = [System.Net.Http.HttpClientHandler]::new()
    $Handler.AllowAutoRedirect = $FollowRedirects

    if ($FollowRedirects) {
        $Handler.MaxAutomaticRedirections = $MaxRedirects
    }

    # Las cookies se leen de las cabeceras Set-Cookie, no del contenedor.
    $Handler.UseCookies = $false

    $Client = [System.Net.Http.HttpClient]::new($Handler)
    $Client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    [void]$Client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", $UserAgent)

    return $Client
}

# GET que devuelve en cuanto llegan las cabeceras (el cuerpo se lee aparte).
function Send-AuditRequest {
    param(
        [System.Net.Http.HttpClient]$Client,
        [string]$Uri
    )

    $Request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::Get,
        $Uri
    )

    return $Client.SendAsync(
        $Request,
        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
    ).GetAwaiter().GetResult()
}

# Resuelve un Location (puede ser relativo) contra la URI solicitada.
function Resolve-Location {
    param(
        [System.Net.Http.HttpResponseMessage]$Response,
        [string]$RequestUri
    )

    $Location = $Response.Headers.Location

    if ($null -eq $Location) { return $null }

    if (-not $Location.IsAbsoluteUri) {
        $Location = [Uri]::new([Uri]$RequestUri, $Location)
    }

    return $Location.AbsoluteUri
}

# Detecta tecnologías a partir de cabeceras, cookies y HTML.
# Es heurístico: una CDN o un proxy pueden ocultar el origen real.
function Get-TechFingerprint {
    param(
        [System.Net.Http.HttpResponseMessage]$Response,
        [string[]]$CookieList,
        [string]$Html
    )

    $Tech = [System.Collections.Generic.List[string]]::new()
    $Add  = { param($t) if (-not $Tech.Contains($t)) { $Tech.Add($t) } }

    # --- Cabeceras ---
    foreach ($H in "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator") {
        $V = Get-HeaderValue $Response $H
        if ($V) { & $Add "$H=$V" }
    }
    if (Get-HeaderValue $Response "X-Drupal-Cache")    { & $Add "Drupal" }
    if (Get-HeaderValue $Response "X-Pingback")        { & $Add "WordPress" }
    if (Get-HeaderValue $Response "X-Litespeed-Cache") { & $Add "LiteSpeed Cache" }
    if (Get-HeaderValue $Response "CF-Ray")            { & $Add "Cloudflare" }

    # --- Cookies ---
    $CookieNames = @($CookieList | Where-Object { $_ } | ForEach-Object { ($_ -split "=", 2)[0].Trim() })
    $CookieRules = [ordered]@{
        '^PHPSESSID$'               = "PHP"
        '^ASP\.NET_SessionId$'      = "ASP.NET"
        '^\.AspNetCore\.'           = "ASP.NET Core"
        '^JSESSIONID$'              = "Java (Servlet)"
        '^laravel_session$'         = "Laravel"
        '^(wordpress_|wp-settings)' = "WordPress"
        '^SS?ESS[0-9a-f]{32}$'      = "Drupal"
        '^csrftoken$'               = "Django"
        '^ci_session$'              = "CodeIgniter"
    }
    foreach ($Rule in $CookieRules.GetEnumerator()) {
        if (@($CookieNames -match $Rule.Key).Count -gt 0) { & $Add $Rule.Value }
    }

    if ($Html) {
        # --- Meta generator ---
        $Gen = [regex]::Match($Html, '(?i)<meta[^>]+name=["'']generator["''][^>]+content=["'']([^"'']+)')
        if (-not $Gen.Success) {
            $Gen = [regex]::Match($Html, '(?i)<meta[^>]+content=["'']([^"'']+)["''][^>]+name=["'']generator')
        }
        if ($Gen.Success) { & $Add "Generator=$($Gen.Groups[1].Value)" }

        # --- Firmas en el HTML ---
        $HtmlRules = [ordered]@{
            '/wp-content/|/wp-includes/'        = "WordPress"
            '/sites/default/files/|/core/misc/' = "Drupal"
            '/media/jui/|/components/com_'      = "Joomla"
            '/_next/static/'                    = "Next.js"
            '__NUXT__|/_nuxt/'                  = "Nuxt"
            'ng-version='                       = "Angular"
            'data-reactroot|react-dom'          = "React"
            'wix\.com|wixstatic\.com'           = "Wix"
            'squarespace'                       = "Squarespace"
            'elementor'                         = "Elementor"
            'bootstrap(\.min)?\.(css|js)'       = "Bootstrap"
            'googletagmanager\.com|gtag\('      = "Google Analytics/GTM"
        }
        foreach ($Rule in $HtmlRules.GetEnumerator()) {
            if ($Html -match "(?i)$($Rule.Key)") { & $Add $Rule.Value }
        }

        # --- Versión de jQuery ---
        $JQ = [regex]::Match($Html, '(?i)jquery[.-]?(\d+\.\d+(\.\d+)?)(\.min)?\.js')
        if ($JQ.Success) { & $Add "jQuery $($JQ.Groups[1].Value)" }

        # --- Tema y plugins de WordPress ---
        $Theme = [regex]::Match($Html, '(?i)/wp-content/themes/([^/"''?]+)')
        if ($Theme.Success) { & $Add "WP tema: $($Theme.Groups[1].Value)" }

        $Plugins = [regex]::Matches($Html, '(?i)/wp-content/plugins/([^/"''?]+)') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        if ($Plugins) { & $Add "WP plugins: $($Plugins -join ', ')" }
    }

    return ($Tech -join " | ")
}

# Consulta un registro TXT (primer valor) con Resolve-DnsName o dig.
function Get-DnsTxt {
    param([string]$Name)

    if ($HasResolveDnsName) {
        $Record = Resolve-DnsName $Name -Type TXT -DnsOnly -ErrorAction Stop |
            Where-Object Type -eq "TXT" | Select-Object -First 1
        return ($Record.Strings -join "")
    }

    if ($HasDig) {
        $Line = & dig +short +time=5 +tries=2 TXT $Name | Select-Object -First 1
        if (-not $Line) { throw "Sin respuesta TXT para $Name" }
        return "$Line".Trim().Trim('"')
    }

    throw "N/D: requiere Resolve-DnsName (Windows) o dig."
}

# ASN y proveedor de una IPv4 vía DNS de Team Cymru (sin tocar el sitio).
function Get-IpAsn {
    param([string]$IPv4)

    $Rev = ($IPv4.Split(".")[3..0]) -join "."

    try {
        # Formato: "ASN | prefijo | país | registro | fecha"
        $Origin = Get-DnsTxt "$Rev.origin.asn.cymru.com"
        $Asn    = ($Origin -split "\|")[0].Trim().Split(" ")[0]

        # Formato: "ASN | país | registro | fecha | nombre"
        $Info = Get-DnsTxt "AS$Asn.asn.cymru.com"
        $Name = (($Info -split "\|")[-1]).Trim()

        return "AS$Asn - $Name"
    }
    catch {
        $Message = Get-ErrorMessage $_
        if ($Message -like "N/D:*") { return "N/D" }
        return "Error: $Message"
    }
}

$HttpNoRedirect = New-AuditHttpClient -FollowRedirects $false
$HttpFollow     = New-AuditHttpClient -FollowRedirects $true

# ------------------------------------------------------------
# INICIO
# ------------------------------------------------------------

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " AUDITORÍA OSINT - MUNICIPIOS DE TLAXCALA" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Municipios: $($Sites.Count)"
Write-Host "Salida:     $OutputDir"

if (-not $HasResolveDnsName) {
    if ($HasDig) {
        Write-Host "DNS:        dig (Resolve-DnsName no disponible)" -ForegroundColor DarkYellow
    }
    else {
        Write-Host "DNS:        .NET (solo A/AAAA; CNAME/NS no disponibles)" -ForegroundColor DarkYellow
    }
}

Write-Host ""

$Counter = 0

# ------------------------------------------------------------
# PROCESAMIENTO
# ------------------------------------------------------------

foreach ($Site in $Sites) {

    $Counter++

    $Municipio = $Site.Municipio
    $Dominio   = $Site.Dominio

    Write-Host ""
    Write-Host "[$Counter/$($Sites.Count)] $Municipio" -ForegroundColor Yellow
    Write-Host "Dominio: $Dominio"

    # --------------------------------------------------------
    # OBJETO BASE
    # --------------------------------------------------------

    $Result = [ordered]@{
        FechaConsulta        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Municipio            = $Municipio
        Dominio              = $Dominio

        IPv4                 = ""
        IPv6                 = ""
        CNAME                = ""
        Nameservers          = ""

        HTTP                 = ""
        HTTP_Status          = ""
        HTTP_Location        = ""
        Redirect_HTTP_HTTPS  = ""

        HTTPS                = ""
        HTTPS_Status         = ""
        HTTPS_URL_Final      = ""

        Server               = ""
        Tecnologias          = ""
        ASN                  = ""
        Reverse_DNS          = ""

        HSTS                = ""
        CSP                  = ""
        X_Frame_Options      = ""
        X_Content_Type       = ""
        Referrer_Policy      = ""
        Permissions_Policy   = ""

        Set_Cookie           = ""
        Cookie_Secure        = ""
        Cookie_HttpOnly      = ""
        Cookie_SameSite      = ""

        TLS                  = ""
        TLS_Cipher           = ""
        Certificate_Valid    = ""
        Certificate_Errors   = ""
        Certificate_Issuer   = ""
        Certificate_Subject  = ""
        Certificate_Expires  = ""
        Certificate_Days_Left = ""

        DNS_Time_ms          = ""
        Connect_Time_ms      = ""
        TLS_Time_ms          = ""
        TTFB_ms              = ""
        Total_Time_ms        = ""

        Error_DNS            = ""
        Error_HTTP           = ""
        Error_HTTPS          = ""
        Error_TLS            = ""

        Observaciones        = ""
    }

    # --------------------------------------------------------
    # DNS A
    # --------------------------------------------------------

    $DnsStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {

        $IPv4 = Resolve-AuditDns -Name $Dominio -Type A

        $DnsStopwatch.Stop()

        if ($IPv4.Count -gt 0) {
            $Result.IPv4 = ($IPv4 -join "; ")
        }

        $Result.DNS_Time_ms = [math]::Round(
            $DnsStopwatch.Elapsed.TotalMilliseconds, 2
        )

    }
    catch {

        $DnsStopwatch.Stop()

        $Message = Get-ErrorMessage $_

        $Result.Error_DNS = $Message

        Add-AuditError `
            -Municipio $Municipio `
            -Dominio $Dominio `
            -Categoria "DNS A" `
            -ErrorMessage $Message
    }

    # --------------------------------------------------------
    # ASN / PROVEEDOR / DNS INVERSO
    # --------------------------------------------------------

    if ($Result.IPv4) {

        $FirstIp = ($Result.IPv4 -split ";\s*")[0]

        $Result.ASN = Get-IpAsn -IPv4 $FirstIp

        try {
            $Result.Reverse_DNS = [System.Net.Dns]::GetHostEntry($FirstIp).HostName
        }
        catch {
            $Result.Reverse_DNS = "Sin PTR"
        }
    }

    # --------------------------------------------------------
    # DNS AAAA / CNAME / NS
    # --------------------------------------------------------

    foreach ($DnsQuery in @(
        @{ Type = "AAAA";  Field = "IPv6" },
        @{ Type = "CNAME"; Field = "CNAME" },
        @{ Type = "NS";    Field = "Nameservers" }
    )) {

        try {

            $Values = Resolve-AuditDns -Name $Dominio -Type $DnsQuery.Type

            if ($Values.Count -gt 0) {
                $Result[$DnsQuery.Field] = ($Values -join "; ")
            }

        }
        catch {

            $Message = Get-ErrorMessage $_

            if ($Message -like "N/D:*") {
                $Result[$DnsQuery.Field] = "N/D"
            }
            else {
                Add-AuditError `
                    -Municipio $Municipio `
                    -Dominio $Dominio `
                    -Categoria "DNS $($DnsQuery.Type)" `
                    -ErrorMessage $Message
            }
        }
    }

    # --------------------------------------------------------
    # HTTP + REDIRECCIÓN HTTP -> HTTPS
    # --------------------------------------------------------
    # Se siguen manualmente hasta $MaxRedirects saltos para
    # detectar cadenas como http://dominio -> http://www -> https://www

    try {

        $CurrentUri = "http://$Dominio/"
        $Hops       = New-Object System.Collections.Generic.List[string]
        $FirstHop   = $true
        $ReachedHttps = $false

        for ($i = 0; $i -le $MaxRedirects; $i++) {

            $HttpResponse = Send-AuditRequest -Client $HttpNoRedirect -Uri $CurrentUri

            try {

                $StatusCode = [int]$HttpResponse.StatusCode
                $Location   = Resolve-Location -Response $HttpResponse -RequestUri $CurrentUri

                if ($FirstHop) {
                    $Result.HTTP          = "Sí"
                    $Result.HTTP_Status   = $StatusCode
                    $Result.HTTP_Location = $Location
                    $FirstHop = $false
                }

            }
            finally {
                $HttpResponse.Dispose()
            }

            if ($StatusCode -lt 300 -or $StatusCode -ge 400 -or -not $Location) {
                break
            }

            $Hops.Add($Location)

            if ($Location -match "^https://") {
                $ReachedHttps = $true
                break
            }

            $CurrentUri = $Location
        }

        if ($ReachedHttps) {
            if ($Hops.Count -eq 1) {
                $Result.Redirect_HTTP_HTTPS = "Sí"
            }
            else {
                $Result.Redirect_HTTP_HTTPS = "Sí ($($Hops.Count) saltos: $($Hops -join ' -> '))"
            }
        }
        elseif ($Hops.Count -gt 0) {
            $Result.Redirect_HTTP_HTTPS = "No - redirección a $($Hops -join ' -> ')"
        }
        else {
            $Result.Redirect_HTTP_HTTPS = "No"
        }

    }
    catch {

        $Message = Get-ErrorMessage $_

        if (-not $Result.HTTP) {
            $Result.HTTP = "No / Error"
        }

        $Result.Redirect_HTTP_HTTPS = "No verificable"
        $Result.Error_HTTP = $Message

        Add-AuditError `
            -Municipio $Municipio `
            -Dominio $Dominio `
            -Categoria "HTTP" `
            -ErrorMessage $Message
    }

    # --------------------------------------------------------
    # HTTPS + CABECERAS + TIEMPOS (TTFB / TOTAL)
    # --------------------------------------------------------

    try {

        $Uri = "https://$Dominio/"

        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $Response = Send-AuditRequest -Client $HttpFollow -Uri $Uri

        try {

            # Cabeceras recibidas = primer byte de la respuesta final
            # (incluye redirecciones previas, si las hubo).
            $Result.TTFB_ms = [math]::Round(
                $Stopwatch.Elapsed.TotalMilliseconds, 2
            )

            $BodyBytes = $Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()

            $Stopwatch.Stop()

            $Result.Total_Time_ms = [math]::Round(
                $Stopwatch.Elapsed.TotalMilliseconds, 2
            )

            $Result.HTTPS           = "Sí"
            $Result.HTTPS_Status    = [int]$Response.StatusCode
            $Result.HTTPS_URL_Final = $Response.RequestMessage.RequestUri.AbsoluteUri

            # ------------------------------------------------
            # CABECERAS
            # ------------------------------------------------

            $Result.Server = Get-HeaderValue $Response "Server"

            $HeaderChecks = [ordered]@{
                HSTS               = "Strict-Transport-Security"
                CSP                = "Content-Security-Policy"
                X_Frame_Options    = "X-Frame-Options"
                X_Content_Type     = "X-Content-Type-Options"
                Referrer_Policy    = "Referrer-Policy"
                Permissions_Policy = "Permissions-Policy"
            }

            foreach ($Field in $HeaderChecks.Keys) {

                $Value = Get-HeaderValue $Response $HeaderChecks[$Field]

                if ($Value) {
                    $Result[$Field] = $Value
                }
                else {
                    $Result[$Field] = "Ausente"
                }
            }

            # ------------------------------------------------
            # COOKIES (se evalúa cada cookie por separado)
            # ------------------------------------------------

            $CookieValues = $null
            $CookieList   = @()

            if ($Response.Headers.TryGetValues("Set-Cookie", [ref]$CookieValues)) {
                $CookieList = @($CookieValues)
            }

            if ($CookieList.Count -gt 0) {

                $Result.Set_Cookie = ($CookieList -join " || ")

                $Total = $CookieList.Count

                $WithSecure   = @($CookieList | Where-Object { $_ -match "(?i);\s*Secure\s*(;|$)" }).Count
                $WithHttpOnly = @($CookieList | Where-Object { $_ -match "(?i);\s*HttpOnly\s*(;|$)" }).Count

                if ($WithSecure -eq $Total) {
                    $Result.Cookie_Secure = "Sí"
                }
                else {
                    $Result.Cookie_Secure = "No ($($Total - $WithSecure) de $Total sin Secure)"
                }

                if ($WithHttpOnly -eq $Total) {
                    $Result.Cookie_HttpOnly = "Sí"
                }
                else {
                    $Result.Cookie_HttpOnly = "No ($($Total - $WithHttpOnly) de $Total sin HttpOnly)"
                }

                $SameSiteValues = foreach ($Cookie in $CookieList) {

                    $Name  = ($Cookie -split "=", 2)[0].Trim()
                    $Match = [regex]::Match($Cookie, "(?i);\s*SameSite=([^;\s]+)")

                    if ($Match.Success) {
                        "$Name=$($Match.Groups[1].Value)"
                    }
                    else {
                        "$Name=No definido"
                    }
                }

                $Result.Cookie_SameSite = ($SameSiteValues -join "; ")
            }
            else {

                $Result.Set_Cookie      = "No detectado"
                $Result.Cookie_Secure   = "N/A"
                $Result.Cookie_HttpOnly = "N/A"
                $Result.Cookie_SameSite = "N/A"
            }

            # ------------------------------------------------
            # TECNOLOGÍAS
            # ------------------------------------------------

            $Html = [System.Text.Encoding]::UTF8.GetString($BodyBytes)

            $Result.Tecnologias = Get-TechFingerprint `
                -Response $Response `
                -CookieList $CookieList `
                -Html $Html

        }
        finally {
            $Response.Dispose()
        }

    }
    catch {

        $Result.HTTPS = "No / Error"

        $Message = Get-ErrorMessage $_

        $Result.Error_HTTPS = $Message

        Add-AuditError `
            -Municipio $Municipio `
            -Dominio $Dominio `
            -Categoria "HTTPS" `
            -ErrorMessage $Message
    }

    # --------------------------------------------------------
    # TLS / CERTIFICADO (+ TIEMPO DE CONEXIÓN TCP)
    # --------------------------------------------------------

    $TcpClient = $null
    $SslStream = $null

    # Estado compartido con el callback de validación.
    $TlsState = @{
        PolicyErrors = $null
        ChainStatus  = $null
    }

    try {

        $TimeoutMs = $TimeoutSeconds * 1000

        $TcpClient = [System.Net.Sockets.TcpClient]::new()
        $TcpClient.ReceiveTimeout = $TimeoutMs
        $TcpClient.SendTimeout    = $TimeoutMs

        $ConnectStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $ConnectTask = $TcpClient.ConnectAsync($Dominio, 443)

        if (-not $ConnectTask.Wait($TimeoutMs)) {
            throw "Timeout ($TimeoutSeconds s) conectando al puerto 443."
        }

        $ConnectStopwatch.Stop()

        $Result.Connect_Time_ms = [math]::Round(
            $ConnectStopwatch.Elapsed.TotalMilliseconds, 2
        )

        $NetworkStream = $TcpClient.GetStream()
        $NetworkStream.ReadTimeout  = $TimeoutMs
        $NetworkStream.WriteTimeout = $TimeoutMs

        # El callback acepta la conexión para poder leer el
        # certificado, pero REGISTRA los errores de validación.
        $ValidationCallback = {
            param($CallbackSender, $Certificate, $Chain, $SslPolicyErrors)

            $TlsState.PolicyErrors = $SslPolicyErrors

            if ($null -ne $Chain -and $Chain.ChainStatus.Count -gt 0) {
                $TlsState.ChainStatus = (
                    $Chain.ChainStatus |
                    ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }
                ) -join " | "
            }

            return $true
        }.GetNewClosure()

        $SslStream = [System.Net.Security.SslStream]::new(
            $NetworkStream,
            $false,
            [System.Net.Security.RemoteCertificateValidationCallback]$ValidationCallback
        )

        $TlsStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Síncrono: el callback de PowerShell debe ejecutarse en este hilo.
        # Los timeouts del NetworkStream evitan que se quede colgado.
        $SslStream.AuthenticateAsClient($Dominio)

        $TlsStopwatch.Stop()

        $Result.TLS_Time_ms = [math]::Round(
            $TlsStopwatch.Elapsed.TotalMilliseconds, 2
        )

        $Result.TLS        = $SslStream.SslProtocol.ToString()
        $Result.TLS_Cipher = $SslStream.NegotiatedCipherSuite.ToString()

        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $SslStream.RemoteCertificate
        )

        $Result.Certificate_Issuer  = $Certificate.Issuer
        $Result.Certificate_Subject = $Certificate.Subject
        $Result.Certificate_Expires = $Certificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
        $Result.Certificate_Days_Left = [math]::Floor(
            ($Certificate.NotAfter - (Get-Date)).TotalDays
        )

        $PolicyErrors = $TlsState.PolicyErrors

        if ($PolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
            $Result.Certificate_Valid  = "Sí"
            $Result.Certificate_Errors = ""
        }
        else {
            $Result.Certificate_Valid = "No"

            $Detail = "$PolicyErrors"

            if ($TlsState.ChainStatus) {
                $Detail += " | $($TlsState.ChainStatus)"
            }

            $Result.Certificate_Errors = $Detail
        }

    }
    catch {

        $Message = Get-ErrorMessage $_

        $Result.Error_TLS = $Message

        Add-AuditError `
            -Municipio $Municipio `
            -Dominio $Dominio `
            -Categoria "TLS" `
            -ErrorMessage $Message
    }
    finally {

        if ($null -ne $SslStream) { $SslStream.Dispose() }
        if ($null -ne $TcpClient) { $TcpClient.Dispose() }
    }

    # --------------------------------------------------------
    # OBSERVACIONES AUTOMÁTICAS
    # --------------------------------------------------------

    $Observaciones = New-Object System.Collections.Generic.List[string]

    if ($Result.HTTPS -ne "Sí") {
        $Observaciones.Add("HTTPS no verificable o no disponible")
    }
    elseif ($Result.HTTPS_Status -ge 400) {
        $Observaciones.Add("HTTPS responde $($Result.HTTPS_Status)")
    }

    if ($Result.HSTS -eq "Ausente") {
        $Observaciones.Add("HSTS ausente")
    }

    if ($Result.CSP -eq "Ausente") {
        $Observaciones.Add("CSP ausente")
    }

    if ($Result.X_Frame_Options -eq "Ausente") {
        $Observaciones.Add("X-Frame-Options ausente")
    }

    if ($Result.X_Content_Type -eq "Ausente") {
        $Observaciones.Add("X-Content-Type-Options ausente")
    }

    if ($Result.Referrer_Policy -eq "Ausente") {
        $Observaciones.Add("Referrer-Policy ausente")
    }

    if ($Result.Permissions_Policy -eq "Ausente") {
        $Observaciones.Add("Permissions-Policy ausente")
    }

    if ($Result.Redirect_HTTP_HTTPS -notlike "Sí*") {
        $Observaciones.Add("HTTP->HTTPS no confirmado")
    }

    if ($Result.Cookie_Secure -like "No*") {
        $Observaciones.Add("Cookies sin atributo Secure")
    }

    if ($Result.Cookie_HttpOnly -like "No*") {
        $Observaciones.Add("Cookies sin HttpOnly")
    }

    if ($Result.Certificate_Valid -eq "No") {
        $Observaciones.Add("Certificado no válido ($($Result.Certificate_Errors))")
    }

    if ($Result.Certificate_Days_Left -ne "" -and
        [int]$Result.Certificate_Days_Left -lt $CertWarnDays) {

        if ([int]$Result.Certificate_Days_Left -lt 0) {
            $Observaciones.Add("Certificado vencido")
        }
        else {
            $Observaciones.Add("Certificado vence en $($Result.Certificate_Days_Left) días")
        }
    }

    if ($Result.TLS -in @("Tls", "Tls11", "Ssl3", "Ssl2")) {
        $Observaciones.Add("Protocolo TLS obsoleto ($($Result.TLS))")
    }

    if ($Result.Error_DNS) {
        $Observaciones.Add("Error DNS")
    }

    if ($Result.Error_HTTP) {
        $Observaciones.Add("Error HTTP")
    }

    if ($Result.Error_HTTPS) {
        $Observaciones.Add("Error HTTPS")
    }

    if ($Result.Error_TLS) {
        $Observaciones.Add("Error TLS")
    }

    $Result.Observaciones = ($Observaciones -join " | ")

    # --------------------------------------------------------
    # GUARDAR RESULTADO
    # --------------------------------------------------------

    $Results.Add([PSCustomObject]$Result)

    Write-Host "  IPv4:  $($Result.IPv4)"
    Write-Host "  HTTP:  $($Result.HTTP) $($Result.HTTP_Status) -> HTTPS: $($Result.Redirect_HTTP_HTTPS)"
    Write-Host "  HTTPS: $($Result.HTTPS) $($Result.HTTPS_Status)"
    Write-Host "  TLS:   $($Result.TLS)  Cert válido: $($Result.Certificate_Valid)"
    Write-Host "  HSTS:  $($Result.HSTS)"
    Write-Host "  Tech:  $($Result.Tecnologias)"
    Write-Host "  ASN:   $($Result.ASN)  PTR: $($Result.Reverse_DNS)"

    if ($Result.Observaciones) {
        Write-Host "  Obs:   $($Result.Observaciones)" -ForegroundColor DarkYellow
    }

    # Pequeña pausa para evitar generar una ráfaga de solicitudes.
    Start-Sleep -Milliseconds 500
}

$HttpNoRedirect.Dispose()
$HttpFollow.Dispose()

# ------------------------------------------------------------
# EXPORTAR RESULTADOS
# ------------------------------------------------------------

$Results |
    Export-Csv `
        -Path $ResultsFile `
        -NoTypeInformation `
        -Encoding utf8BOM

$Errors |
    Export-Csv `
        -Path $ErrorsFile `
        -NoTypeInformation `
        -Encoding utf8BOM

# ------------------------------------------------------------
# RESUMEN
# ------------------------------------------------------------

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host " AUDITORÍA FINALIZADA" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Municipios procesados : $($Sites.Count)"
Write-Host "Resultados            : $ResultsFile"
Write-Host "Errores               : $ErrorsFile"
Write-Host ""

Write-Host "Errores registrados: $($Errors.Count)" -ForegroundColor Yellow
Write-Host ""
