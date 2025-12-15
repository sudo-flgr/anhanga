🦅 ANHANGÁ - Cyber Intelligence Framework (Alpha 1.0)
Orquestrador de Inteligência para Investigações de Fraudes Digitais e Infraestrutura Hostil. Foco: Rastreio de Pix, Laranjas e Operações de 'Bets' ilegais.

📋 Sobre o Projeto
O Anhangá é uma ferramenta de CLI (Linha de Comando) desenvolvida para acelerar o ciclo de inteligência em investigações cibernéticas no contexto brasileiro. Ele atua como um "analista virtual" que ingere dados brutos (Pix, URLs), enriquece-os através de múltiplas fontes (OSINT) e utiliza Inteligência Artificial Local para gerar dossiês completos.

A ferramenta foi desenhada para combater a "fadiga de abas", centralizando em um único terminal o que levaria horas para ser coletado manualmente.

🚀 Módulos & Funcionalidades
1. 💰 FinCrime (Rastreio Financeiro)
Pix Decoder: Decodificação nativa de payloads EMV ("Copia e Cola") para extração de beneficiários, chaves e cidades.

Validador de Laranjas: Consulta automática de CNPJs na Receita Federal (BrasilAPI) para identificar empresas de fachada.

2. 🦅 InfraInt (Infraestrutura Resiliente)
Estratégia "Multi-Vetor" que garante resultados mesmo contra proteções (WAF/Cloudflare):

Favicon Hash: Rastreamento de servidores reais via MurmurHash3.

Shodan Híbrido: Consulta via Hash (Premium) ou via Host IP (Free/Bypass).

Whois Intelligence: Dados de registro de domínio, e-mails e datas de criação.

Certificate Transparency (CRT): Mapeamento de subdomínios históricos.

VirusTotal: Análise de reputação e detecção de malware.

3. 🧠 AI Core (O Cérebro)
Analista Cognitivo: Integração com Ollama (Modelo Phi-3) para ler os dados estruturados (JSON) e redigir um Relatório de Inteligência em linguagem natural (PT-BR).

Análise de Contratos: Leitura automatizada de Termos de Uso para extração de Entidades Legais e Licenças.

4. 🕸️ Graph Intelligence (Visualização)
Mapas Interativos: Geração de grafos de vínculos em HTML (PyVis), permitindo visualização dinâmica de redes de lavagem de dinheiro e infraestrutura compartilhada.

🛠️ Instalação
Pré-requisitos
Python 3.10+

Ollama instalado e rodando (ollama.com)

Modelo sugerido: ollama run phi3

Configuração Rápida
Clone o repositório e instale as dependências:

Bash

pip install -r requirements.txt
(Dependências principais: typer, rich, requests, ollama, shodan, python-whois, pyvis)

Configure suas chaves de API (Opcional, mas recomendado): O Anhangá possui um gerenciador de segredos criptografado localmente.

Bash

python main.py config --set-shodan "SUA_KEY_SHODAN"
python main.py config --set-vt "SUA_KEY_VIRUSTOTAL"
🎮 Como Usar
🧙‍♂️ Modo Wizard (Recomendado)
O Anhangá guia você por toda a investigação, do Pix ao Relatório Final.

Bash

python main.py investigate
O assistente irá:

Solicitar o código Pix (para identificar o financeiro).

Solicitar a URL do alvo (para mapear a infraestrutura).

Processar os dados em tempo real.

Acionar a IA para escrever o dossiê.

Gerar e abrir o Grafo de Vínculos no seu navegador.

⚡ Comandos Individuais (Modo Manual)
Se preferir usar ferramentas específicas:

Iniciar/Limpar Operação: python main.py start

Adicionar Pix: python main.py add-pix --pix "000201..."

Investigar Site: python main.py add-url --url "site.com"

Gerar Grafo: python main.py graph

📂 Estrutura do Projeto
anhanga/
├── main.py                 # Orquestrador (CLI Typer)
├── investigation_current.json # Banco de Dados da Sessão (JSON)
├── core/
│   ├── database.py         # Gerenciador de Estado
│   └── config.py           # Gerenciador de Chaves
└── modules/
    ├── fincrime/           # Pix Decoder & Validador CNPJ
    ├── infra/              # Hunter (Shodan, Whois, VT, CRT) & Analyzer
    ├── graph/              # Gerador de Visualização (PyVis)
    └── reporter/           # Redator de IA (Ollama)
    
⚠️ Disclaimer
Esta ferramenta é uma Prova de Conceito (PoC) desenvolvida para fins de Defesa Cibernética e Inteligência de Ameaças. O uso para atividades ilícitas é estritamente proibido.

Desenvolvido por Felipe L. G. Rodrigues Alpha v1.0
