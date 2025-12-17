# 🌿 ANHANGÁ

> **Financial Crime & Cyber Threat Intelligence Framework**

![Version](https://img.shields.io/badge/version-2.1-green)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Focus](https://img.shields.io/badge/focus-Defense%20%26%20Intelligence-red)

## 👹 A Origem & O Propósito

Na mitologia Tupi-Guarani, o **Anhangá** é o espírito protetor da floresta. Ele vaga pela mata com seus olhos de fogo, protegendo o ecossistema e perseguindo aqueles que caçam por ganância, crueldade ou desrespeito.

**No mundo digital, a infraestrutura é a nossa floresta.**

O Projeto Anhangá v2.1 foi concebido com essa filosofia: um framework de defesa e inteligência para caçar fraudadores ("Bets" ilegais, esquemas de lavagem via Pix e Laranjas) que exploram o ecossistema digital brasileiro. Ele centraliza em um terminal o trabalho que exigiria dezenas de ferramentas dispersas.

---

## 🚀 Arquitetura & Capacidades (v2.1)

O Anhangá deixou de ser apenas um script linear e tornou-se um framework modular, operado por uma **Investigation Engine** proprietária que carrega plugins dinamicamente.

### 💰 1. Rastreio Financeiro (Follow the Money)
Focado nas peculiaridades do sistema bancário brasileiro e na nova economia cripto.

* **Pix Forensics (Nativo):** Implementação pura da norma EMV (ISO 18004) em Python.
    * **Validação Matemática:** Verifica a integridade do payload via algoritmo **CRC16-CCITT**.
    * **Extração Profunda:** Recupera Nome do Recebedor, Cidade, TXID e a Chave Pix real mascarada.
* **Crypto Hunter:** Detecção automática e rastreio de carteiras de **Bitcoin, Ethereum e Tron**.
    * Verificação de saldos em tempo real.
    * Geração de links forenses para exploradores de bloco.

### 🦅 2. Infraestrutura & Dirty Scraping
Não apenas consultamos o DNS; nós lemos o código-fonte como um atacante faria.

* **Hunter v2 (Dirty Scraper):** Baixa o HTML do alvo e utiliza Regex avançado para encontrar "pegadas digitais" ocultas:
    * **IDs de Rastreio:** Google Analytics (`UA-XXXX`), GTM (`G-XXXX`) e Pixels. Isso permite vincular sites diferentes à mesma quadrilha.
    * **Contatos Ocultos:** E-mails de desenvolvedores e telefones esquecidos em comentários de código.
* **Resiliência:** Fallback automático para dados históricos de DNS e Whois caso o site esteja protegido por WAF/Cloudflare.

### 👁️ 3. Identidade Digital (De-anonymization)
Focado em desmascarar "laranjas" e operadores técnicos.

* **Identity Hunter:** Valida a presença digital de e-mails suspeitos.
    * **Visualint:** Recupera fotos reais e nomes de usuário via **Gravatar**.
    * **SociaL:** Verifica vínculos em plataformas como Spotify e Skype.
* **Leak Intelligence:** Cruzamento automatizado com bases de vazamentos (Google Dorks especializados) para confirmar a veracidade de credenciais.

### 🧠 4. AI Core (Analista Cognitivo)
Integração com **Ollama (LLMs Locais)** para transformar dados técnicos (JSON) em relatórios jurídicos/policiais.
* Gera dossiês completos em PT-BR, correlacionando o Pix, o IP e a Identidade em uma narrativa de investigação.

---

## 🛠️ Instalação

### Pré-requisitos
* **Python 3.10+**
* **Ollama** (para relatórios de IA): [https://ollama.com](https://ollama.com)
    * Sugestão de modelo: `ollama run phi3` ou `llama3`

### Configuração Rápida

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/SEU-USUARIO/anhanga.git](https://github.com/SEU-USUARIO/anhanga.git)
    cd anhanga
    ```

2.  **Instale as dependências (Incluindo CRCMod e Rich):**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Inicie o Framework:**
    ```bash
    python anhanga.py investigate
    ```

---

## 🎮 Como Usar

### 🕵️‍♂️ Modo Investigação (Pipeline Completo)
O comando principal que aciona todos os motores sequencialmente:

```bash
python anhanga.py investigate
