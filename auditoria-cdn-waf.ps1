#Requires -Version 7.0
# ============================================================
# AUDITORÍA OSINT - CDN / WAF DE PORTALES MUNICIPALES DE TLAXCALA
# ============================================================
#
# Requisitos:
#   PowerShell 7+ (Windows, Linux o macOS)
#   - En Windows se usa Resolve-DnsName.
#   - En Linux/macOS se usa "dig" si está instalado; si no,
#     CNAME y ASN quedan como N/D.
#
# Detecta CDN, WAF y balanceadores de forma PASIVA a partir de:
#   - Cadena CNAME del dominio
#   - ASN / proveedor de la IP (DNS de Team Cymru)
#   - DNS inverso (PTR)
#   - Cabeceras y cookies de UNA petición GET a la portada
#   - Firmas en el HTML de esa misma respuesta
#
# NO realiza:
#   - envío de cargas maliciosas para provocar al WAF
#   - escaneo de puertos
#   - fuzzing ni enumeración de rutas
#   - evasión de WAF ni búsqueda de la IP de origen
#
# Si un dominio no muestra firmas, se reporta "No detectado":
# puede existir un WAF de red u hosting sin rastro visible.
#
# Uso:
#   pwsh -File .\auditoria-cdn-waf.ps1
#   pwsh -File .\auditoria-cdn-waf.ps1 -SoloDominios apizaco.gob.mx,tlaxco.gob.mx
# ============================================================

param(
    # Opcional: auditar solo estos dominios de la lista.
    [string[]]$SoloDominios
)

# ------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------

$OutputDir = Join-Path $PSScriptRoot "auditoria-cdn-waf"

$ResultsFile = Join-Path $OutputDir "cdn_waf_resultados.csv"
$ErrorsFile  = Join-Path $OutputDir "cdn_waf_errores.csv"

$TimeoutSeconds = 20
$MaxRedirects   = 5

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
# FIRMAS DE CDN / WAF
# ------------------------------------------------------------
# Cada firma puede tener:
#   Headers : @{ "Nombre" = "regex del valor" }  ("" = basta con que exista)
#   Cookies : regex sobre el NOMBRE de la cookie
#   Cname   : regex sobre cualquier nombre de la cadena CNAME
#   Asn     : lista de números de ASN
#   Ptr     : regex sobre el DNS inverso
#   Html    : regex sobre el HTML de la portada
#   Cdn/Waf : qué capacidades implica la detección

$Signatures = @(
    @{
        Proveedor = "Cloudflare"; Cdn = $true; Waf = $true
        Headers   = @{ "CF-Ray" = ""; "CF-Cache-Status" = ""; "cf-mitigated" = ""; "Server" = '(?i)^cloudflare' }
        Cookies   = '^(__cf_bm|cf_clearance|__cfruid|_cfuvid)$'
        Cname     = '(?i)\.cdn\.cloudflare\.net$'
        Asn       = @(13335, 209242)
        Html      = '(?i)Attention Required! \| Cloudflare|challenges\.cloudflare\.com|cf-browser-verification'
    },
    @{
        Proveedor = "Akamai"; Cdn = $true; Waf = $false
        Headers   = @{ "Server" = '(?i)AkamaiGHost|AkamaiNetStorage'; "X-Akamai-Transformed" = ""; "Akamai-GRN" = "" }
        Cname     = '(?i)\.(edgekey|edgesuite|akamaiedge|akamaihd|akamaized)\.net$'
        Asn       = @(20940, 16625, 16702, 21342)
        Ptr       = '(?i)akamaitechnologies\.com$|akamai'
        Html      = '(?i)errors\.edgesuite\.net'
    },
    @{
        Proveedor = "Akamai Bot Manager / Kona WAF"; Cdn = $false; Waf = $true
        Cookies   = '^(ak_bmsc|bm_sz|_abck|bm_sv)$'
        Asn       = @(32787)
    },
    @{
        Proveedor = "AWS CloudFront"; Cdn = $true; Waf = $false
        Headers   = @{ "X-Amz-Cf-Id" = ""; "X-Amz-Cf-Pop" = ""; "Via" = '(?i)cloudfront'; "Server" = '(?i)^CloudFront' }
        Cname     = '(?i)\.cloudfront\.net$'
        Ptr       = '(?i)\.cloudfront\.net$'
    },
    @{
        Proveedor = "AWS WAF"; Cdn = $false; Waf = $true
        Headers   = @{ "x-amzn-waf-action" = "" }
        Cookies   = '^aws-waf-token$'
        Html      = '(?i)awswaf\.com|captcha\.awswaf'
    },
    @{
        Proveedor = "Fastly"; Cdn = $true; Waf = $false
        Headers   = @{ "X-Fastly-Request-ID" = ""; "Fastly-Debug-Digest" = ""; "X-Served-By" = '(?i)^cache-' }
        Cname     = '(?i)\.(fastly|fastlylb)\.net$'
        Asn       = @(54113)
    },
    @{
        Proveedor = "Azure Front Door / Azure CDN"; Cdn = $true; Waf = $false
        Headers   = @{ "X-Azure-Ref" = ""; "X-MSEdge-Ref" = "" }
        Cname     = '(?i)\.(azurefd|azureedge|afd\.azureedge)\.net$'
    },
    @{
        Proveedor = "Sucuri"; Cdn = $true; Waf = $true
        Headers   = @{ "X-Sucuri-ID" = ""; "X-Sucuri-Cache" = ""; "Server" = '(?i)Sucuri|Cloudproxy' }
        Cookies   = '^sucuri_cloudproxy'
        Asn       = @(30148)
        Html      = '(?i)Sucuri WebSite Firewall|sucuri\.net/privacy-policy'
    },
    @{
        Proveedor = "Imperva / Incapsula"; Cdn = $true; Waf = $true
        Headers   = @{ "X-Iinfo" = ""; "X-CDN" = '(?i)Imperva|Incapsula' }
        Cookies   = '^(visid_incap_|incap_ses_|nlbi_)'
        Cname     = '(?i)\.incapdns\.net$'
        Asn       = @(19551)
        Html      = '(?i)Incapsula incident ID|_Incapsula_Resource'
    },
    @{
        Proveedor = "F5 BIG-IP (balanceador)"; Cdn = $false; Waf = $false
        Headers   = @{ "Server" = '(?i)BigIP|BIG-IP' }
        Cookies   = '^BIGipServer'
    },
    @{
        Proveedor = "F5 BIG-IP ASM / Advanced WAF"; Cdn = $false; Waf = $true
        Cookies   = '^TS[0-9a-f]{6,}$'
        Html      = '(?i)The requested URL was rejected\. Please consult with your administrator'
    },
    @{
        Proveedor = "Barracuda WAF"; Cdn = $false; Waf = $true
        Cookies   = '^(barra_counter_session|BNI__BARRACUDA_LB_COOKIE|BNI_persistence)'
        Html      = '(?i)Barracuda Web Application Firewall'
    },
    @{
        Proveedor = "Wordfence (WAF de WordPress)"; Cdn = $false; Waf = $true
        Cookies   = '^wfwaf-authcookie'
        Html      = '(?i)/wp-content/plugins/wordfence|Generated by Wordfence'
    }
)

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

# Devuelve el mensaje de la excepción más interna.
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

# Resuelve IPv4 y la cadena CNAME completa del dominio.
function Resolve-DnsChain {
    param([string]$Name)

    $Chain = @()
    $IPv4  = @()

    if ($HasResolveDnsName) {

        $Records = Resolve-DnsName -Name $Name -Type A -DnsOnly -ErrorAction Stop

        $Chain = @($Records | Where-Object { $_.Type -eq "CNAME" } |
                   Select-Object -ExpandProperty NameHost)
        $IPv4  = @($Records | Where-Object { $_.Type -eq "A" } |
                   Select-Object -ExpandProperty IPAddress)
    }
    elseif ($HasDig) {

        # dig +short muestra los CNAME intermedios y luego las IPs.
        $Output = & dig +short +time=5 +tries=2 A $Name 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "dig terminó con código $LASTEXITCODE`: $($Output -join ' ')"
        }

        foreach ($Line in @($Output | ForEach-Object { "$_".Trim() } | Where-Object { $_ })) {
            if ($Line -match '^\d{1,3}(\.\d{1,3}){3}$') { $IPv4  += $Line }
            else                                       { $Chain += $Line.TrimEnd('.') }
        }
    }
    else {

        $IPv4 = @([System.Net.Dns]::GetHostAddresses($Name) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.ToString() })

        $Chain = $null   # N/D sin Resolve-DnsName ni dig
    }

    return [PSCustomObject]@{ IPv4 = $IPv4; Cname = $Chain }
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

    # Formato: "ASN | prefijo | país | registro | fecha"
    $Origin = Get-DnsTxt "$Rev.origin.asn.cymru.com"
    $Asn    = [int](($Origin -split "\|")[0].Trim().Split(" ")[0])

    # Formato: "ASN | país | registro | fecha | nombre"
    $Info = Get-DnsTxt "AS$Asn.asn.cymru.com"
    $Name = (($Info -split "\|")[-1]).Trim()

    return [PSCustomObject]@{ Numero = $Asn; Texto = "AS$Asn - $Name" }
}

function Limit-Text {
    param([string]$Text, [int]$Max = 80)

    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max) + "…"
}

# Aplica las firmas y devuelve un objeto por proveedor detectado.
function Find-EdgeProviders {
    param(
        [System.Net.Http.HttpResponseMessage]$Response,
        [string[]]$CookieNames,
        [string[]]$CnameChain,
        [int]$AsnNumber,
        [string]$Ptr,
        [string]$Html
    )

    $Found = New-Object System.Collections.Generic.List[object]

    foreach ($Sig in $Signatures) {

        $Evidence = New-Object System.Collections.Generic.List[string]

        if ($Sig.Headers -and $Response) {
            foreach ($HeaderName in $Sig.Headers.Keys) {
                $Value   = Get-HeaderValue $Response $HeaderName
                $Pattern = $Sig.Headers[$HeaderName]

                if ($null -ne $Value -and (-not $Pattern -or $Value -match $Pattern)) {
                    $Evidence.Add("Cabecera $HeaderName`: $(Limit-Text $Value)")
                }
            }
        }

        if ($Sig.Cookies) {
            foreach ($Cookie in @($CookieNames -match $Sig.Cookies)) {
                $Evidence.Add("Cookie $Cookie")
            }
        }

        if ($Sig.Cname) {
            foreach ($Cname in @($CnameChain -match $Sig.Cname)) {
                $Evidence.Add("CNAME $Cname")
            }
        }

        if ($Sig.Asn -and $AsnNumber -and ($Sig.Asn -contains $AsnNumber)) {
            $Evidence.Add("ASN $AsnNumber")
        }

        if ($Sig.Ptr -and $Ptr -and $Ptr -match $Sig.Ptr) {
            $Evidence.Add("PTR $Ptr")
        }

        if ($Sig.Html -and $Html) {
            $Match = [regex]::Match($Html, $Sig.Html)
            if ($Match.Success) {
                $Evidence.Add("HTML: $(Limit-Text $Match.Value 60)")
            }
        }

        if ($Evidence.Count -gt 0) {
            $Found.Add([PSCustomObject]@{
                Proveedor = $Sig.Proveedor
                Cdn       = $Sig.Cdn
                Waf       = $Sig.Waf
                Evidencia = @($Evidence)
            })
        }
    }

    return $Found.ToArray()
}

# Cliente HTTP que sigue redirecciones y lee cookies desde Set-Cookie.
$Handler = [System.Net.Http.HttpClientHandler]::new()
$Handler.AllowAutoRedirect        = $true
$Handler.MaxAutomaticRedirections = $MaxRedirects
$Handler.UseCookies               = $false

$HttpClient = [System.Net.Http.HttpClient]::new($Handler)
$HttpClient.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
[void]$HttpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", $UserAgent)

# ------------------------------------------------------------
# INICIO
# ------------------------------------------------------------

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " AUDITORÍA CDN / WAF - MUNICIPIOS DE TLAXCALA" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Municipios: $($Sites.Count)"
Write-Host "Salida:     $OutputDir"

if (-not $HasResolveDnsName -and -not $HasDig) {
    Write-Host "DNS:        .NET (CNAME y ASN no disponibles; instala dig)" -ForegroundColor DarkYellow
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

    $Result = [ordered]@{
        FechaConsulta = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Municipio     = $Municipio
        Dominio       = $Dominio

        IPv4          = ""
        CNAME         = ""
        ASN           = ""
        Reverse_DNS   = ""

        URL_Final     = ""
        HTTP_Status   = ""
        Server        = ""

        CDN           = ""
        WAF           = ""
        Otros         = ""
        Estado        = ""
        Evidencias    = ""

        Error_DNS     = ""
        Error_ASN     = ""
        Error_HTTP    = ""
    }

    $CnameChain = @()
    $AsnNumber  = 0
    $Ptr        = ""

    # --------------------------------------------------------
    # DNS: IPv4 + CADENA CNAME
    # --------------------------------------------------------

    try {

        $Dns = Resolve-DnsChain -Name $Dominio

        $Result.IPv4 = ($Dns.IPv4 -join "; ")

        if ($null -eq $Dns.Cname) {
            $Result.CNAME = "N/D"
        }
        else {
            $CnameChain   = @($Dns.Cname)
            $Result.CNAME = ($CnameChain -join " -> ")
        }

    }
    catch {

        $Message = Get-ErrorMessage $_
        $Result.Error_DNS = $Message

        Add-AuditError -Municipio $Municipio -Dominio $Dominio `
            -Categoria "DNS" -ErrorMessage $Message
    }

    # --------------------------------------------------------
    # ASN + DNS INVERSO
    # --------------------------------------------------------

    if ($Result.IPv4) {

        $FirstIp = ($Result.IPv4 -split ";\s*")[0]

        try {
            $AsnInfo    = Get-IpAsn -IPv4 $FirstIp
            $AsnNumber  = $AsnInfo.Numero
            $Result.ASN = $AsnInfo.Texto
        }
        catch {
            $Message = Get-ErrorMessage $_

            if ($Message -like "N/D:*") {
                $Result.ASN = "N/D"
            }
            else {
                $Result.Error_ASN = $Message
                Add-AuditError -Municipio $Municipio -Dominio $Dominio `
                    -Categoria "ASN" -ErrorMessage $Message
            }
        }

        try {
            $Ptr = [System.Net.Dns]::GetHostEntry($FirstIp).HostName
            $Result.Reverse_DNS = $Ptr
        }
        catch {
            $Result.Reverse_DNS = "Sin PTR"
        }
    }

    # --------------------------------------------------------
    # PETICIÓN A LA PORTADA (HTTPS; HTTP si HTTPS falla)
    # --------------------------------------------------------

    $Response    = $null
    $Html        = ""
    $CookieNames = @()
    $HttpErrors  = @()

    foreach ($Scheme in "https", "http") {

        try {

            $Request = [System.Net.Http.HttpRequestMessage]::new(
                [System.Net.Http.HttpMethod]::Get,
                "${Scheme}://$Dominio/"
            )

            $Response = $HttpClient.SendAsync(
                $Request,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()

            $Bytes = $Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            $Html  = [System.Text.Encoding]::UTF8.GetString($Bytes)

            break
        }
        catch {

            $HttpErrors += "$($Scheme.ToUpper()): $(Get-ErrorMessage $_)"

            if ($null -ne $Response) {
                $Response.Dispose()
                $Response = $null
            }
        }
    }

    if ($HttpErrors.Count -gt 0) {

        $Result.Error_HTTP = ($HttpErrors -join " | ")

        Add-AuditError -Municipio $Municipio -Dominio $Dominio `
            -Categoria "HTTP" -ErrorMessage $Result.Error_HTTP
    }

    if ($null -ne $Response) {

        $Result.URL_Final   = $Response.RequestMessage.RequestUri.AbsoluteUri
        $Result.HTTP_Status = [int]$Response.StatusCode
        $Result.Server      = Get-HeaderValue $Response "Server"

        $SetCookies = $null
        if ($Response.Headers.TryGetValues("Set-Cookie", [ref]$SetCookies)) {
            $CookieNames = @($SetCookies | ForEach-Object { ($_ -split "=", 2)[0].Trim() })
        }
    }

    # --------------------------------------------------------
    # DETECCIÓN
    # --------------------------------------------------------

    try {

        $Found = Find-EdgeProviders `
            -Response $Response `
            -CookieNames $CookieNames `
            -CnameChain $CnameChain `
            -AsnNumber $AsnNumber `
            -Ptr $Ptr `
            -Html $Html

        $Label = { param($P) "$($P.Proveedor) ($($P.Evidencia.Count) señal$(if ($P.Evidencia.Count -ne 1) { 'es' }))" }

        $Result.CDN   = (@($Found | Where-Object Cdn) | ForEach-Object { & $Label $_ }) -join "; "
        $Result.WAF   = (@($Found | Where-Object Waf) | ForEach-Object { & $Label $_ }) -join "; "
        $Result.Otros = (@($Found | Where-Object { -not $_.Cdn -and -not $_.Waf }) |
                         ForEach-Object { & $Label $_ }) -join "; "

        $Result.Evidencias = (@($Found) | ForEach-Object {
            "$($_.Proveedor): $($_.Evidencia -join ', ')"
        }) -join " || "

        if (-not $Result.CDN) { $Result.CDN = "No detectado" }
        if (-not $Result.WAF) { $Result.WAF = "No detectado" }

        $Estado = New-Object System.Collections.Generic.List[string]

        if ($null -eq $Response) {
            $Estado.Add("Sin respuesta HTTP: detección solo por DNS/ASN")
        }
        elseif ($Result.HTTP_Status -in 403, 429, 503 -and @($Found | Where-Object Waf).Count -gt 0) {
            $Estado.Add("Respuesta $($Result.HTTP_Status): posible bloqueo o desafío del WAF")
        }

        if (@($Found).Count -eq 0) {
            $Estado.Add("Sin firmas de CDN/WAF (puede existir protección sin rastro visible)")
        }
        elseif (@($Found | Where-Object Cdn).Count -gt 0 -and @($Found | Where-Object Waf).Count -eq 0) {
            $Estado.Add("CDN detectado; WAF no confirmado")
        }

        $Result.Estado = ($Estado -join " | ")

    }
    catch {

        $Message = Get-ErrorMessage $_

        $Result.CDN    = "Error"
        $Result.WAF    = "Error"
        $Result.Estado = "Error en la detección: $Message"

        Add-AuditError -Municipio $Municipio -Dominio $Dominio `
            -Categoria "Detección" -ErrorMessage $Message
    }
    finally {
        if ($null -ne $Response) { $Response.Dispose() }
    }

    # --------------------------------------------------------
    # GUARDAR RESULTADO
    # --------------------------------------------------------

    $Results.Add([PSCustomObject]$Result)

    Write-Host "  IPv4:  $($Result.IPv4)"
    Write-Host "  CNAME: $($Result.CNAME)"
    Write-Host "  ASN:   $($Result.ASN)  PTR: $($Result.Reverse_DNS)"
    Write-Host "  HTTP:  $($Result.HTTP_Status)  Server: $($Result.Server)"
    Write-Host "  CDN:   $($Result.CDN)" -ForegroundColor Cyan
    Write-Host "  WAF:   $($Result.WAF)" -ForegroundColor Cyan

    if ($Result.Otros) {
        Write-Host "  Otros: $($Result.Otros)"
    }

    if ($Result.Estado) {
        Write-Host "  Obs:   $($Result.Estado)" -ForegroundColor DarkYellow
    }

    # Pequeña pausa para evitar generar una ráfaga de solicitudes.
    Start-Sleep -Milliseconds 500
}

$HttpClient.Dispose()

# ------------------------------------------------------------
# EXPORTAR RESULTADOS
# ------------------------------------------------------------

$Results |
    Export-Csv -Path $ResultsFile -NoTypeInformation -Encoding utf8BOM

$Errors |
    Export-Csv -Path $ErrorsFile -NoTypeInformation -Encoding utf8BOM

# ------------------------------------------------------------
# RESUMEN
# ------------------------------------------------------------

$ConCdn = @($Results | Where-Object { $_.CDN -notin "No detectado", "Error" }).Count
$ConWaf = @($Results | Where-Object { $_.WAF -notin "No detectado", "Error" }).Count

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host " AUDITORÍA FINALIZADA" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Municipios procesados : $($Sites.Count)"
Write-Host "Con CDN detectado     : $ConCdn"
Write-Host "Con WAF detectado     : $ConWaf"
Write-Host "Resultados            : $ResultsFile"
Write-Host "Errores               : $ErrorsFile"
Write-Host ""

Write-Host "Errores registrados: $($Errors.Count)" -ForegroundColor Yellow
Write-Host ""
