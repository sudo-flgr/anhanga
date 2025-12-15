# 🦅 ANHANGÁ

## Cyber Intelligence Framework (Alpha v1.0)

**Orquestrador de Inteligência para Investigações de Fraudes Digitais e Infraestrutura Hostil**
**Foco:** Rastreio de Pix, identificação de laranjas e operações ilegais de *bets*.

---

## 📋 Sobre o Projeto

O **Anhangá** é uma ferramenta de **CLI (Command-Line Interface)** desenvolvida para acelerar o ciclo de inteligência em investigações cibernéticas no contexto brasileiro.

Ele atua como um **analista virtual**, ingerindo dados brutos (Pix, URLs), enriquecendo-os por meio de múltiplas fontes **OSINT** e aplicando **Inteligência Artificial local** para gerar **dossiês de inteligência completos**.

O projeto foi concebido para combater a chamada *"fadiga de abas"*, centralizando em um único terminal atividades que normalmente demandaria mais tempo de coleta e correlação manual.

---

## 🚀 Módulos & Funcionalidades

### 💰 FinCrime — Rastreio Financeiro

* **Pix Decoder**
  Decodificação nativa de payloads EMV (*Copia e Cola*) para extração de:

  * Beneficiários
  * Chaves Pix
  * Cidades e instituições

* **Validador de Laranjas**
  Consulta automática de **CNPJs** via **Receita Federal (BrasilAPI)** para identificação de empresas de fachada.

---

### 🦅 InfraInt — Inteligência de Infraestrutura

Estratégia **Multi-Vetor**, projetada para obter resultados mesmo sob proteções como **WAF** e **Cloudflare**.

* **Favicon Hash**
  Rastreamento de servidores reais via **MurmurHash3**.

* **Shodan Híbrido**

  * Consulta por *Hash* (Premium)
  * Consulta por *Host/IP* (Free / Bypass)

* **WHOIS Intelligence**
  Coleta de dados de registro de domínio, e-mails e datas de criação.

* **Certificate Transparency (CRT)**
  Mapeamento de subdomínios históricos.

* **VirusTotal**
  Análise de reputação e detecção de malware.

---

### 🧠 AI Core — O Cérebro

* **Analista Cognitivo**
  Integração com **Ollama** (modelo **Phi-3**) para leitura de dados estruturados (JSON) e redação automática de **Relatórios de Inteligência em PT-BR**.

* **Análise de Contratos**
  Leitura automatizada de *Termos de Uso* para extração de:

  * Entidades legais
  * Licenças

---

### 🕸️ Graph Intelligence — Visualização

* **Mapas Interativos**
  Geração de grafos de vínculos em **HTML** utilizando **PyVis**, permitindo análise dinâmica de:

  * Redes de lavagem de dinheiro
  * Infraestrutura compartilhada

---

## 🛠️ Instalação

### Pré-requisitos

* **Python 3.10+**
* **Ollama** instalado e em execução: [https://ollama.com](https://ollama.com)
* Modelo sugerido:

```bash
ollama run phi3
```

---

### Configuração Rápida

Clone o repositório e instale as dependências:

```bash
pip install -r requirements.txt
```

**Dependências principais:**

* typer
* rich
* requests
* ollama
* shodan
* python-whois
* pyvis

---

### Configuração de APIs (Opcional, mas recomendado)

O Anhangá possui um **gerenciador de segredos criptografado localmente**.

```bash
python anhanga.py config --set-shodan "SUA_KEY_SHODAN"
python anhanga.py config --set-vt "SUA_KEY_VIRUSTOTAL"
```

---

## 🎮 Como Usar

### 🧙‍♂️ Modo Wizard (Recomendado)

O Anhangá guia você por toda a investigação, do Pix ao Relatório Final:

```bash
python anhanga.py investigate
```

O assistente irá:

1. Solicitar o código Pix
2. Solicitar a URL do alvo
3. Processar e enriquecer os dados em tempo real
4. Acionar a IA para redigir o dossiê
5. Gerar e abrir o grafo de vínculos no navegador

---

### ⚡ Comandos Individuais (Modo Manual)

```bash
# Iniciar ou limpar operação
python anhanga.py start

# Adicionar Pix
python anhanga.py add-pix --pix "000201..."

# Investigar site
python anhanga.py add-url --url "site.com"

# Gerar grafo
python anhanga.py graph
```

---

## 📂 Estrutura do Projeto

```text
anhanga/
├── anhanga.py                     # Orquestrador (CLI Typer)
├── investigation_current.json  # Banco de dados da sessão
├── core/
│   ├── database.py             # Gerenciador de estado
│   └── config.py               # Gerenciador de chaves
└── modules/
    ├── fincrime/               # Pix Decoder & Validador CNPJ
    ├── infra/                  # Hunter (Shodan, Whois, VT, CRT)
    ├── graph/                  # Visualização (PyVis)
    └── reporter/               # Redator de IA (Ollama)
```

---

## ⚠️ Disclaimer

Esta ferramenta é uma **Prova de Conceito (PoC)** desenvolvida exclusivamente para **Defesa Cibernética**, **Inteligência de Ameaças** e **pesquisa**.

O uso para atividades ilícitas é **estritamente proibido**.

---

## 👤 Autor

**Felipe L. G. Rodrigues**
Alpha v1.0
