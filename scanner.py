#!/usr/bin/env python3
"""Scanner TCP educacional com verificações HTTP/TLS. Uso autorizado."""
import argparse
import concurrent.futures
import csv
import html
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

VERSION = "2.0.0"
DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"
SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",111:"rpcbind",135:"MS-RPC",139:"NetBIOS",143:"IMAP",
    443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP submission",
    993:"IMAPS",995:"POP3S",1433:"SQL Server",1521:"Oracle DB",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",
    6379:"Redis",8080:"HTTP alternate",8443:"HTTPS alternate",
    9200:"Elasticsearch",27017:"MongoDB"
}
RISKY = {
    21:("MEDIUM","FTP potencialmente exposto","Avalie FTPS/SFTP e restrinja o acesso."),
    23:("HIGH","Telnet potencialmente exposto","Prefira SSH e restrinja o acesso."),
    445:("MEDIUM","SMB potencialmente exposto","Restrinja SMB às redes necessárias."),
    3389:("MEDIUM","RDP potencialmente exposto","Considere VPN, allowlist e MFA."),
    5900:("MEDIUM","VNC potencialmente exposto","Confirme autenticação, criptografia e restrições."),
    6379:("HIGH","Redis potencialmente exposto","Restrinja o serviço e confirme autenticação."),
    9200:("HIGH","Elasticsearch potencialmente exposto","Confirme autenticação e controles de acesso."),
    27017:("HIGH","MongoDB potencialmente exposto","Confirme autenticação e controles de acesso."),
    3306:("MEDIUM","MySQL potencialmente exposto","Restrinja o banco às redes necessárias."),
    5432:("MEDIUM","PostgreSQL potencialmente exposto","Restrinja o banco às redes necessárias."),
    1433:("MEDIUM","SQL Server potencialmente exposto","Restrinja o banco às redes necessárias."),
}

def parse_target(raw):
    value = raw.strip()
    parts = urlsplit(value if "://" in value else "//" + value)
    if parts.username or parts.password:
        raise ValueError("Não informe credenciais na URL.")
    if not parts.hostname or any(c.isspace() for c in parts.hostname):
        raise ValueError("Alvo inválido. Informe domínio ou IP.")
    return parts.hostname

def parse_ports(spec):
    found = set()
    try:
        for item in spec.split(","):
            item = item.strip()
            if not item:
                continue
            if "-" in item:
                a, b = map(int, item.split("-", 1))
                if a > b:
                    raise ValueError(f"Intervalo inválido: {item}")
                found.update(range(a, b + 1))
            else:
                found.add(int(item))
    except (ValueError, TypeError) as exc:
        raise ValueError("Use portas como 22,80,443 ou intervalo 1-1024.") from exc
    if not found or min(found) < 1 or max(found) > 65535:
        raise ValueError("Portas devem estar entre 1 e 65535.")
    if len(found) > 4096:
        raise ValueError("Limite de 4096 portas por execução.")
    return sorted(found)

def make_finding(severity, title, location, evidence, recommendation, confidence="needs_review"):
    return {"severity":severity,"title":title,"location":location,
            "evidence":evidence,"recommendation":recommendation,"confidence":confidence}

def scan_port(host, port, timeout):
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            state = "open"
    except ConnectionRefusedError:
        state = "closed"
    except (socket.timeout, TimeoutError):
        state = "no_response"
    except OSError as exc:
        return {"port":port,"state":"error","service":SERVICES.get(port,"unknown"),"error":str(exc)}
    return {"port":port,"state":state,"service":SERVICES.get(port,"unknown"),
            "response_ms":round((time.monotonic()-started)*1000,2)}

def check_tls(host, timeout, findings, checks):
    entry = {"check":"TLS certificate","target":f"{host}:443","status":"not_confirmed"}
    try:
        with socket.create_connection((host,443),timeout=timeout) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as conn:
                cert = conn.getpeercert()
                version = conn.version()
                entry.update(status="ok",tls_version=version,certificate_validation="passed")
                expiry = cert.get("notAfter")
                if expiry:
                    date = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry),timezone.utc)
                    days = (date-datetime.now(timezone.utc)).days
                    entry.update(expires_at_utc=date.isoformat(),days_until_expiry=days)
                    if days < 0:
                        findings.append(make_finding("HIGH","Certificado TLS expirado",host,
                            date.isoformat(),"Renove e instale um certificado válido.","confirmed"))
                    elif days <= 30:
                        findings.append(make_finding("LOW","Certificado TLS próximo da expiração",host,
                            f"Expira em {days} dia(s).","Renove antes da expiração.","confirmed"))
                if version in ("TLSv1","TLSv1.1","SSLv3","SSLv2"):
                    findings.append(make_finding("MEDIUM","Protocolo TLS antigo negociado",host,
                        version,"Desabilite protocolos obsoletos.","confirmed"))
    except ssl.SSLCertVerificationError as exc:
        entry.update(status="certificate_validation_failed",error=str(exc))
        findings.append(make_finding("HIGH","Falha na validação TLS",host,str(exc),
            "Verifique validade, cadeia de confiança e nome do certificado.","confirmed"))
    except (OSError,ssl.SSLError,TimeoutError) as exc:
        entry["error"] = str(exc)
    checks.append(entry)

def check_web(host, timeout, findings, checks):
    context = ssl.create_default_context()
    for scheme in ("http","https"):
        url = f"{scheme}://{host}/"
        req = Request(url,headers={"User-Agent":f"TCP-Port-Scanner/{VERSION}"})
        try:
            response = urlopen(req,timeout=timeout,context=context)
        except HTTPError as exc:
            response = exc
        except (URLError,OSError,TimeoutError,ssl.SSLError) as exc:
            checks.append({"check":scheme.upper(),"url":url,"status":"not_confirmed","error":str(exc)})
            continue
        with response:
            status, final_url, headers = response.code,response.geturl(),response.headers
            entry = {"check":scheme.upper(),"url":url,"final_url":final_url,
                     "http_status":status,"status":"responded"}
            checks.append(entry)
            if status >= 500:
                findings.append(make_finding("INFO","Resposta HTTP 5xx",final_url,
                    f"HTTP {status}; isso não comprova vulnerabilidade.",
                    "Investigue os logs e o funcionamento da aplicação."))
            if scheme == "http" and not final_url.startswith("https://"):
                findings.append(make_finding("LOW","HTTP não redirecionou para HTTPS",final_url,
                    f"URL final em HTTP; status {status}.",
                    "Se apropriado, configure redirecionamento para HTTPS.","needs_review"))
            if scheme == "https":
                for name, severity, advice in [
                    ("Strict-Transport-Security","LOW","Avalie HSTS para o domínio."),
                    ("Content-Security-Policy","INFO","Avalie uma CSP adequada à aplicação."),
                    ("X-Content-Type-Options","INFO","Avalie a diretiva nosniff."),
                    ("Referrer-Policy","INFO","Defina uma política de referenciador apropriada."),
                    ("Permissions-Policy","INFO","Restrinja APIs do navegador conforme necessário.")
                ]:
                    if name not in headers:
                        findings.append(make_finding(severity,f"Cabeçalho ausente: {name}",final_url,
                            f"O servidor não enviou {name}; ausência isolada não prova falha.",
                            advice))
                exposed = "; ".join(x for x in [
                    f"Server: {headers['Server']}" if headers.get("Server") else "",
                    f"X-Powered-By: {headers['X-Powered-By']}" if headers.get("X-Powered-By") else ""
                ] if x)
                if exposed:
                    findings.append(make_finding("INFO","Cabeçalho revela tecnologia",final_url,
                        exposed,"Considere reduzir detalhes de versão quando apropriado.","confirmed"))
                break

def assess_ports(ports, findings):
    for item in ports:
        if item["state"] != "open":
            continue
        port = item["port"]
        if port in RISKY:
            severity,title,advice = RISKY[port]
            findings.append(make_finding(severity,title,f"TCP/{port}",
                f"Conexão TCP aceita; serviço inferido pela porta: {item['service']}.",
                advice))
        elif port not in (80,443,8080,8443):
            findings.append(make_finding("INFO","Porta TCP aberta",f"TCP/{port}",
                f"Conexão aceita; serviço provável: {item['service']}.",
                "Confirme se a exposição é necessária e aplique controles de acesso.","confirmed"))

def render_html(report):
    rows = []
    for f in report["findings"]:
        rows.append("<tr>"+"".join(f"<td>{html.escape(str(f.get(k,'')))}</td>"
            for k in ("severity","title","location","evidence","recommendation"))+"</tr>")
    ports = "".join("<tr>"+"".join(f"<td>{html.escape(str(p.get(k,'')))}</td>"
        for k in ("port","state","service","response_ms"))+"</tr>" for p in report["ports"])
    return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Relatório TCP Scanner</title>
<style>body{{font:15px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#17202a}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}th,td{{border:1px solid #ccd2d8;padding:.5rem;text-align:left;overflow-wrap:anywhere}}
th{{background:#eef3f8}}.note{{background:#fff4d6;padding:1rem}}</style><body>
<h1>TCP Port Scanner — relatório</h1><p><b>Alvo:</b> {html.escape(report['target'])}</p>
<p><b>Data UTC:</b> {html.escape(report['timestamp_utc'])}</p>
<div class="note">Os achados são sinais para revisão e não confirmam automaticamente vulnerabilidades.</div>
<h2>Achados</h2><table><tr><th>Severidade</th><th>Achado</th><th>Local</th><th>Evidência</th><th>Recomendação</th></tr>
{''.join(rows)}</table><h2>Portas</h2><table><tr><th>Porta</th><th>Estado</th><th>Serviço</th><th>ms</th></tr>
{ports}</table><h2>Checagens HTTP/TLS</h2><pre>{html.escape(json.dumps(report['checks'],ensure_ascii=False,indent=2))}</pre>
</body></html>"""

def main():
    parser = argparse.ArgumentParser(description="Scanner TCP e verificações HTTP/TLS para auditorias autorizadas.")
    parser.add_argument("target",help="Domínio ou IP autorizado para teste")
    parser.add_argument("--ports",default=DEFAULT_PORTS,help='Ex.: "22,80,443" ou "1-1024"')
    parser.add_argument("--timeout",type=float,default=1.2)
    parser.add_argument("--workers",type=int,default=64)
    parser.add_argument("--out",default="scan-report",help="Prefixo dos relatórios HTML/JSON/CSV")
    parser.add_argument("--no-web-checks",action="store_true")
    args = parser.parse_args()
    try:
        host = parse_target(args.target)
        ports = parse_ports(args.ports)
        if not 0.1 <= args.timeout <= 30:
            raise ValueError("Timeout deve estar entre 0.1 e 30 segundos.")
        if not 1 <= args.workers <= 128:
            raise ValueError("Workers devem estar entre 1 e 128.")
        socket.getaddrinfo(host,None)
    except (ValueError,OSError) as exc:
        print(f"[ERRO] {exc}",file=sys.stderr)
        return 2
    print(f"TCP Port Scanner v{VERSION} | alvo: {host} | portas: {len(ports)}")
    print("Use somente em sistemas próprios ou com autorização explícita.\n")
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda p: scan_port(host,p,args.timeout),ports))
    findings, checks = [], []
    assess_ports(results,findings)
    if not args.no_web_checks:
        check_tls(host,args.timeout,findings,checks)
        check_web(host,args.timeout,findings,checks)
    findings.sort(key=lambda f:{"HIGH":0,"MEDIUM":1,"LOW":2,"INFO":3}.get(f["severity"],4))
    report = {"tool":"TCP Port Scanner","version":VERSION,"target":host,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "duration_seconds":round(time.monotonic()-start,2),"ports_scanned":len(ports),
        "ports":results,"checks":checks,"findings":findings,
        "summary":{"open_ports":sum(p["state"]=="open" for p in results),
        "findings":len(findings),"high":sum(f["severity"]=="HIGH" for f in findings),
        "medium":sum(f["severity"]=="MEDIUM" for f in findings),
        "low":sum(f["severity"]=="LOW" for f in findings)},
        "disclaimer":"Achados limitados; valide manualmente. Porta aberta ou cabeçalho ausente não prova vulnerabilidade."}
    prefix = Path(args.out)
    prefix.parent.mkdir(parents=True,exist_ok=True)
    prefix.with_suffix(".json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    prefix.with_suffix(".html").write_text(render_html(report),encoding="utf-8")
    with prefix.with_suffix(".csv").open("w",newline="",encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle,fieldnames=["severity","title","location","evidence","recommendation","confidence"])
        writer.writeheader()
        writer.writerows(findings)
    for item in results:
        if item["state"]=="open":
            print(f"[ABERTA] TCP/{item['port']} — {item['service']} ({item.get('response_ms','?')} ms)")
    confirmed = [
        f for f in findings
        if f.get("confidence") == "confirmed"
        and f.get("severity") in ("HIGH", "MEDIUM", "LOW")
    ]
    print(f"\nPortas abertas: {report['summary']['open_ports']}")
    print(f"Vulnerabilidades confirmadas: {len(confirmed)}")
    for f in confirmed:
        print(f"[{f['severity']}] {f['title']} — {f['location']}")
    print("\nRelatórios detalhados gerados:")
    for ext in (".html",".json",".csv"):
        print(f"  {prefix.with_suffix(ext)}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAnálise interrompida.",file=sys.stderr)
        raise SystemExit(130)
