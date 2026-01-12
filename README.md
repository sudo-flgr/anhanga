que elas ficam locais e fora do Git).

Copie o bloco abaixo e substitua no seu arquivo.

Markdown

# Anhangá - Advanced Financial Crime & Threat Intelligence Platform

<div align="center">
  <img src="assets/logo.png" alt="Anhangá Logo" width="450">
  <br><br>
  
  <a href="https://github.com/felipeluan20/anhanga">
    <img src="https://img.shields.io/badge/version-3.0.0-blue" alt="Version">
  </a>
  <a href="https://python.org">
    <img src="https://img.shields.io/badge/python-3.12+-blue" alt="Python">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/architecture-LangGraph%20%2F%20Async-orange" alt="Architecture">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/focus-Financial%20Crimes%20%26%20Compliance-red" alt="Focus">
  </a>
</div>

## 📖 Visão Geral

O **Anhangá v3.0** é uma plataforma de Inteligência de Ameaças (CTI) focada especificamente no combate a crimes financeiros digitais, lavagem de dinheiro e na fiscalização do mercado de apostas online ("Bets") no Brasil.

Diferente de scanners tradicionais que focam apenas em infraestrutura de rede, o Anhangá opera na camada de aplicação e financeira. Ele utiliza uma arquitetura baseada em **Grafos de Agentes Autônomos (LangGraph)** para simular o comportamento de um analista humano: navegando em sites, evadindo proteções (WAF), extraindo vetores financeiros (PIX/Cripto) e validando a conformidade legal do alvo contra as regulações vigentes (Lei 14.790).

## 🚀 Arquitetura v3.0 (Capacidades)

A versão 3.0 representa uma evolução completa do motor, operando como uma **Máquina de Estados Assíncrona**.

### 1. Motor de Investigação Híbrido (LangGraph)
O núcleo do sistema toma decisões de roteamento baseadas na defesa do alvo:
* **Detecção de WAF:** Identifica automaticamente proteções como Cloudflare.
* **Stealth Mode (Camoufox):** Aciona um navegador *headless* com fingerprint evasiva para renderizar JavaScript complexo e capturar evidências visuais (screenshots) sem ser bloqueado.

### 2. MoneyTrail & Compliance (Fluxo Financeiro)
Foco no rastreamento do dinheiro ("Follow the Money"):
* **Pix Forensics (EMV):** Extrai e decodifica QR Codes e "Copia e Cola" diretamente da memória. Revela o Beneficiário Real, Cidade e Instituição Financeira.
* **Compliance Check (Lei 14.790):** Cruza o operador do site com a base oficial de autorizações do Governo Federal.
* **Orange Risk:** Algoritmo de *Fuzzy Matching* que detecta discrepâncias entre a Marca do Site e o Beneficiário do Pix (indício de Laranjas).

### 3. Enriquecimento de Inteligência (OSINT)
Visão 360º da infraestrutura através da correlação de dados internos e externos:
* **Coleta Local:** Raspagem de E-mails, Telefones e Tecnologias (Analytics/Pixels).
* **Shodan Integration:** Identificação de portas abertas, vulnerabilidades (CVEs) e organização do ASN.
* **Whois & URLScan:** Dados de registro de domínio e histórico de varreduras passadas.
* **VirusTotal:** Análise de reputação e detecção de malware em tempo real.

### 4. Relatórios Executivos (IA)
Geração de dossiês em linguagem natural utilizando LLMs locais (Ollama/Phi-3).
* Transforma dados técnicos JSON em um relatório jurídico/policial pronto para tomada de decisão.

---

## 🛠️ Instalação

### Pré-requisitos
* **Python 3.12+** (Obrigatório para suporte a AsyncIO moderno).
* **Ollama** (Opcional, apenas para relatórios de IA): [https://ollama.com](https://ollama.com)

### Setup Rápido

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/felipeluan20/anhanga.git](https://github.com/felipeluan20/anhanga.git)
    cd anhanga
    ```

2.  **Instale as dependências:**
    ```bash
    pip install -e .
    ```

3.  **Verifique a instalação:**
    ```bash
    python -m anhanga.cli version
    ```

---

## 💻 Uso (CLI)

O Anhangá v3.0 possui uma Interface de Linha de Comando (CLI) profissional, localizada em Português (PT-BR).

### 1. Configuração de Chaves (Opcional mas Recomendado)
Para ativar o poder total do módulo de OSINT (Shodan, VirusTotal, URLScan), configure suas chaves de API.
*Nota: As chaves são salvas localmente e ignoradas pelo Git para segurança.*

```bash
python -m anhanga.cli config \
  --set-vt "SUA_CHAVE_VIRUSTOTAL" \
  --set-shodan "SUA_CHAVE_SHODAN" \
  --set-urlscan "SUA_CHAVE_URLSCAN"
```
### 2. Iniciar uma Investigação
** Executa o motor completo (Infra + Compliance + MoneyTrail + OSINT).**

Bash
```
python -m anhanga.cli scan [https://alvo.com](https://alvo.com)
```
### 3. Investigação com Dossiê de IA
Adicione a flag **--report** para que a IA analise os dados e escreva um relatório Markdown final.

```
python -m anhanga.cli scan [https://alvo.com](https://alvo.com) --report
```
** (Requer Ollama rodando localmente)**

## 📂 Estrutura do Projeto
```
src/anhanga/
├── cli.py               # Interface CLI (Typer/Rich) & Camada de Tradução
├── core/
│   ├── engine.py        # Motor LangGraph (Grafo de Decisão)
│   └── config.py        # Gerenciador de Segredos (Ignora JSON no Git)
└── modules/
    ├── infra/           # Scrapers (Local) e Conectores API (Shodan/VT)
    ├── fincrime/        # Decodificadores PIX (EMV) e Validação Legal
    ├── crypto/          # Extratores de Carteiras (Regex Contextual)
    └── reporter/        # Agente de Redação (IA/Ollama)
```
## ⚖️ Disclaimer Legal
Esta ferramenta é uma **Prova de Conceito (PoC)** desenvolvida estritamente para fins acadêmicos e de pesquisa em Segurança Cibernética, Compliance e Inteligência Financeira.

**O uso do Anhangá deve estar em conformidade com todas as leis locais (incluindo LGPD e Marco Civil da Internet). O desenvolvedor sudo-flgr não se responsabiliza pelo uso indevido desta ferramenta para atividades não autorizadas.**
