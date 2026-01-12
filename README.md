# Anhangá - Asynchronous Threat Intelligence Platform

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

O **Anhangá v3.0** é uma plataforma de Inteligência de Ameaças (CTI) focada especificamente no combate a crimes financeiros digitais e na fiscalização do mercado de apostas online ("Bets") no Brasil.

Diferente de scanners tradicionais que focam apenas em infraestrutura de rede (IP/DNS), o Anhangá opera na camada de aplicação e financeira. Ele utiliza uma arquitetura baseada em **Grafos de Agentes Autônomos (LangGraph)** para simular o comportamento de um analista humano: navegando em sites, evadindo proteções (WAF), extraindo vetores financeiros (PIX/Cripto) e validando a conformidade legal do alvo contra as regulações vigentes.

## 🚀 Arquitetura v3.0 (Novas Capacidades)

A versão 3.0 representa uma reescrita completa do motor, migrando de scripts lineares para uma **Máquina de Estados Assíncrona**.

### 1. Motor de Investigação Assíncrono (LangGraph)
O núcleo do sistema não segue mais um fluxo rígido. Ele toma decisões de roteamento baseadas no alvo:
* **Detecção de Proteção:** Identifica automaticamente WAFs como Cloudflare.
* **Roteamento Adaptativo:**
    * *Rota Padrão:* Scrapers HTTP leves para alvos desprotegidos.
    * *Rota Stealth:* Aciona o módulo **Camoufox** (Headless Browser com Fingerprint evasiva) para renderizar JavaScript e capturar evidências visuais (screenshots) em alvos protegidos.

### 2. MoneyTrail & Compliance (Fluxo Financeiro)
O foco principal da v3.0 é o rastreamento do dinheiro ("Follow the Money"):
* **Extração de PIX (EMV):** Algoritmo capaz de extrair QR Codes e Strings "Copia e Cola" diretamente da memória do navegador ou do HTML. Decodifica o payload EMV (ISO 18004) para revelar o Beneficiário Real, Cidade e TXID.
* **Validação de Compliance ("Orange Check"):**
    * Consulta a base de dados oficial de operadores autorizados (Lei 14.790/2023).
    * Realiza um cruzamento (Fuzzy Matching) entre a Marca do Site e o Beneficiário do PIX.
    * **Alerta de Risco:** Identifica discrepâncias que indicam uso de contas laranjas ou lavagem de dinheiro (ex: Site "BetX" recebendo em nome de "João Silva MEI").

### 3. Coleta Profunda de Infraestrutura
Resgate das capacidades de "Dirty Scraping" da versão anterior, agora integradas ao fluxo assíncrono:
* **Fingerprinting:** Coleta IP real do servidor, Hash de Favicon (para correlação no Shodan) e Stack Tecnológica (Analytics, Pixels).
* **Extração de Contatos:** Scraping recursivo de e-mails e telefones ocultos no código-fonte para atribuição de autoria.

### 4. Relatórios Inteligentes (IA Opcional)
Geração de dossiês executivos utilizando LLMs locais (via Ollama/Phi-3).
* O relatório correlaciona os dados técnicos (Infra + Financeiro + Legal) em uma narrativa investigativa pronta para uso por departamentos de Compliance ou Jurídico.

---

## 🛠️ Instalação

### Pré-requisitos
* **Python 3.12+** (Necessário para suporte a Typing moderno e AsyncIO).
* **Ollama** (Opcional, apenas para relatórios de IA): [https://ollama.com](https://ollama.com)

### Setup

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/felipeluan20/anhanga.git](https://github.com/felipeluan20/anhanga.git)
    cd anhanga
    ```

2.  **Instale em modo editável:**
    ```bash
    pip install -e .
    ```

3.  **Verifique a instalação:**
    ```bash
    python -m anhanga.cli version
    ```

---

## 💻 Uso (CLI)

O Anhangá v3.0 possui uma Interface de Linha de Comando (CLI) unificada e profissional.

### Iniciar uma Investigação
Executa o motor completo (Infra + Compliance + MoneyTrail).

```bash
python -m anhanga.cli scan [https://alvo.com](https://alvo.com)
Investigação com Relatório IA
Adicione a flag --report para gerar um dossiê Markdown ao final.
 ```
Bash
 ```
python -m anhanga.cli scan [https://alvo.com](https://alvo.com) --report
 ```
**(Requer Ollama rodando localmente)**


Gerenciamento de Chaves
Para enriquecimento de dados (opcional).

Bash
 ```
python -m anhanga.cli config --set-vt "SUA_API_KEY"
📂 Estrutura do Projeto
Plaintext

src/anhanga/
├── cli.py               # Ponto de entrada (Typer/Rich)
├── core/
│   ├── engine.py        # Cérebro: Grafo de Agentes (LangGraph)
│   └── config.py        # Gerenciador de Configuração
└── modules/
    ├── infra/           # Scrapers de Rede e WAF Bypass
    ├── fincrime/        # Decodificadores PIX e Validadores
    ├── crypto/          # Extratores de Carteiras (Regex Contextual)
    └── compliance/      # Verificação Legal (Lei 14.790)
 ```

##⚖️ Disclaimer Legal
Esta ferramenta é uma Prova de Conceito (PoC) desenvolvida estritamente para fins acadêmicos e de pesquisa em Segurança Cibernética e Inteligência Financeira.

O uso do :**Anhangá:** deve estar em conformidade com todas as leis locais, nacionais e internacionais aplicáveis. Os desenvolvedores não se responsabilizam pelo uso indevido desta ferramenta para atividades não autorizadas.
