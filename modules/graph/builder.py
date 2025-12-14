# Arquivo: anhanga/modules/graph/builder.py
from pyvis.network import Network
import os
import webbrowser

class GraphBrain:
    def __init__(self):
        # Configura o Canvas: Fundo Preto, Fonte Branca, 100% da tela
        self.net = Network(height="750px", width="100%", bgcolor="#111111", font_color="white")
        
        # Física dos nós (Evita que fiquem um em cima do outro)
        self.net.force_atlas_2based()

    def add_fincrime_data(self, nome_laranja, doc):
        """Adiciona Nó de Pessoa/Empresa"""
        # Ícone de usuário ou prédio
        self.net.add_node(nome_laranja, label=nome_laranja, title=f"Alvo: {nome_laranja}\nDoc: {doc}", color="#ff3333", shape="dot", value=20)
        
        # Adiciona o documento como um nó menor conectado
        self.net.add_node(doc, label=doc, color="#ff8080", shape="box", size=10)
        self.net.add_edge(nome_laranja, doc, color="#555555")

    def add_infra_data(self, domain, ip_real):
        """Adiciona Nó de Infraestrutura"""
        # Nó do Site
        self.net.add_node(domain, label=domain, title=f"Site: {domain}\nIP: {ip_real}", color="#3333ff", shape="dot", value=20)
        
        # Nó do IP
        self.net.add_node(ip_real, label=ip_real, color="#00ffff", shape="box", size=10)
        self.net.add_edge(domain, ip_real, color="#555555")

    def connect_entities(self, source, target, relation_type):
        """Cria o vínculo com uma seta explicativa"""
        self.net.add_edge(source, target, title=relation_type, label=relation_type, color="#ffff00", width=2, arrows="to")

    def plot_investigation(self):
        """Gera o HTML interativo e abre no navegador"""
        output_file = "investigation_map.html"
        
        # Opções visuais avançadas (Física)
        self.net.set_options("""
        var options = {
          "nodes": {
            "font": {
              "size": 16,
              "face": "tahoma"
            }
          },
          "edges": {
            "color": {
              "inherit": true
            },
            "smooth": false
          },
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -50,
              "centralGravity": 0.01,
              "springLength": 100,
              "springConstant": 0.08
            },
            "minVelocity": 0.75,
            "solver": "forceAtlas2Based"
          }
        }
        """)
        
        self.net.save_graph(output_file)
        print(f"[bold green][*] Mapa Tático gerado: {output_file}[/bold green]")
        
        # Tenta abrir no navegador padrão
        try:
            webbrowser.open('file://' + os.path.realpath(output_file))
        except:
            print(f"Abra o arquivo {output_file} manualmente no seu navegador.")