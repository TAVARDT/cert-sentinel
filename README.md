# TAVARDT Certificate Sentinel: TLS/SSL Watchdog

<div align="center">
  <p>Automated TLS/SSL certificate & chain integrity watchdog. Designed for high-ticket B2B digital protection.</p>
  <p>
    <a href="#english">🇺🇸 English</a> | 
    <a href="#portugues">🇧🇷 Português</a>
  </p>
</div>

***

<h2 id="english">🇺🇸 English</h2>

### Overview
This repository contains the official TAVARDT certificate monitoring utility for production environments. Unplanned SSL certificate expirations break user trust, ruin SEO rankings, and cause catastrophic downtime in B2B transactions. Certificate Sentinel automates non-intrusive TLS/SSL inspections, validates intermediate trust chains, detects compromised certificate authorities (CAs), and dispatches early warning alerts before an incident occurs.

### 🚨 IMPORTANT: Alert Thresholds & Safe Defaults
Certificate Sentinel evaluates certificate health using a dual-tiered risk matrix:
* **Warning Threshold (`<= 30 days`):** Flags certificates requiring scheduled renewal during the next maintenance window.
* **Critical Threshold (`<= 15 days`):** High-urgency alert indicating imminent service disruption.
* **Safe Inspection Mode:** Uses standard OpenSSL SNI handshakes. It does not alter web server configurations or disrupt active user sessions.

### Security Layers
* **Expiration Telemetry:** Precise day-by-day countdown to certificate expiration.
* **Trust Chain & CA Verification:** Detects untrusted root CAs, self-signed certificates, and known compromised issuers (e.g. eMudhra PKI incident).
* **Protocol & Cipher Suite Audit:** Inspects negotiated TLS version (TLS 1.2 / TLS 1.3) and detects deprecated ciphers.
* **Multi-Domain & Multi-Channel Alerting:** Batch auditing via text files and automated webhook dispatch to Slack, Discord, Telegram, or internal SIEM systems.

### Usage

#### Quick Run (Single Domain):
```bash
bash sentinel.sh example.com
```

#### Batch Inspection (Multiple Domains):
Create a `domains.txt` file with one domain per line:
```bash
bash sentinel.sh --file domains.txt
```

#### Automated Webhook Alerting (Cron Daemon):
Schedule daily checks at 06:00 AM and send alerts to your webhook endpoint:
```bash
0 6 * * * WEBHOOK_URL="https://discord.com/api/webhooks/..." /bin/bash /opt/cert-sentinel/sentinel.sh --file /opt/cert-sentinel/domains.txt >> /var/log/cert-sentinel.log 2>&1
```

#### Python CLI (JSON Output):
```bash
python3 sentinel.py example.com --json
```

### Contact & Services
Looking for elite cybersecurity, zero-trust architecture, or incident recovery?
* Website: [ag.tavardt.com/cybersecurity](https://ag.tavardt.com/cybersecurity)
* Email: [contact@tavardt.com](mailto:contact@tavardt.com)

***

<h2 id="portugues">🇧🇷 Português</h2>

### Visão Geral
Este repositório contém o utilitário oficial de monitoramento de certificados da TAVARDT para ambientes de produção. Expirações imprevistas de certificados SSL destroem a confiança de clientes, derrubam posições no Google e causam paradas catastróficas em transações B2B. O Certificate Sentinel automatiza a inspeção de TLS/SSL, valida cadeias de confiança intermediárias, detecta autoridades certificadoras (CAs) comprometidas e dispara alertas preventivos antes que um incidente aconteça.

### 🚨 IMPORTANTE: Limiares de Alerta & Modo Seguro
O Certificate Sentinel avalia a saúde dos certificados através de uma matriz de risco de dois níveis:
* **Limiar de Aviso (`<= 30 dias`):** Identifica certificados que devem ser renovados na próxima janela de manutenção programada.
* **Limiar Crítico (`<= 15 dias`):** Alerta de urgência máxima indicando risco iminente de interrupção de serviço.
* **Modo de Inspeção Seguro:** Utiliza handshakes TLS padrão via OpenSSL SNI. Não altera configurações de servidores web nem impacta sessões de usuários ativos.

### Camadas de Segurança
* **Telemetria de Expiração:** Contagem precisa dia a dia até a expiração do certificado.
* **Cadeia de Confiança & Auditoria de CA:** Identifica certificados autoassinados, cadeias quebradas e emissores sob alerta de segurança (ex: incidente eMudhra PKI).
* **Auditoria de Cifras & Protocolos:** Inspeciona versões negociadas de TLS (TLS 1.2 / TLS 1.3) e sinaliza cifras legadas vulneráveis.
* **Auditoria em Lote & Notificação Multicanal:** Suporte a arquivos de múltiplos domínios e envio automático de webhooks para Slack, Discord, Telegram ou SIEM interno.

### Uso

#### Execução Rápida (Domínio Único):
```bash
bash sentinel.sh example.com.br
```

#### Inspeção em Lote (Múltiplos Domínios):
Crie um arquivo `domains.txt` com um domínio por linha:
```bash
bash sentinel.sh --file domains.txt
```

#### Agendamento com Alerta via Webhook (Cron Diário):
Monitore todos os dias às 06:00 e envie notificações caso haja certificados críticos:
```bash
0 6 * * * WEBHOOK_URL="https://discord.com/api/webhooks/..." /bin/bash /opt/cert-sentinel/sentinel.sh --file /opt/cert-sentinel/domains.txt >> /var/log/cert-sentinel.log 2>&1
```

#### Execução em Python (Saída Estruturada JSON):
```bash
python3 sentinel.py example.com.br --json
```

### Contato & Serviços
Procurando por cibersegurança de elite, arquitetura zero-trust ou auditoria de infraestrutura?
* Site: [ag.tavardt.com/br/ciberseguranca/](https://ag.tavardt.com/br/ciberseguranca/)
* E-mail: [contato@tavardt.com](mailto:contato@tavardt.com)
