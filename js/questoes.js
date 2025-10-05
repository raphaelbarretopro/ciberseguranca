// ==========================================
// Arquivo: questoes.js
// Descrição: Contém todas as questões do simulado AZ-900
// ==========================================

export const questoes = [

  {
  "tipo": "unica",
  "texto": "Qual das seguintes opções é uma prática recomendada para se defender contra ataques de acesso, como adivinhação de senhas?",
  "opcoes": [
    "Usar o mesmo firewall para redes internas e externas.",
    "Permitir o acesso de qualquer endereço IP para facilitar o trabalho remoto.",
    "Implementar uma política de senhas fortes e autenticação multifator (MFA).",
    "Desativar todo o registro de logs para melhorar o desempenho do sistema."
  ],
  "resposta": 2,
  "explicacao": "A implementação de uma **política de senhas fortes** (comprimento, complexidade e rotação) dificulta ataques de força bruta e adivinhação de senhas. A **Autenticação Multifator (MFA)** adiciona uma camada de segurança essencial ao exigir uma segunda forma de verificação (algo que você tem ou algo que você é) além da senha (algo que você sabe), protegendo as contas mesmo que a senha seja comprometida.",
  "dominio": "Protegendo Redes"
},
  {
  "tipo": "unica",
  "texto": "Qual tipo de ameaça é frequentemente considerada mais perigosa para uma organização devido ao acesso direto a instalações e conhecimento interno da rede?",
  "opcoes": [
    "Vulnerabilidades de software",
    "Ameaças externas",
    "Ameaças internas",
    "Ataques de negação de serviço (DoS)"
  ],
  "resposta": 2,
  "explicacao": "Ameaças internas são consideradas as mais perigosas porque os funcionários ou parceiros já possuem acesso legítimo aos sistemas e conhecimento detalhado da infraestrutura, permitindo que causem danos mais significativos e difíceis de serem detectados.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Um invasor liga para a secretária de um executivo, fingindo ser do suporte de TI e alegando que os arquivos de uma apresentação importante estão corrompidos. Ele a pressiona para enviar os arquivos imediatamente para um e-mail pessoal para 'corrigi-los'. Que tática de engenharia social está sendo usada?",
  "opcoes": [
    "Intimidação",
    "Algo por algo (Quid pro quo)",
    "Pretexting (Pré-diálogo)",
    "Consenso (Prova social)"
  ],
  "resposta": 0,
  "explicacao": "A tática de **Intimidação** (também conhecida como Coerção) é utilizada quando o atacante usa pressão, ameaças ou medo de consequências negativas (como a perda do emprego ou outros danos) para forçar a vítima a tomar uma ação rápida, ignorando protocolos de segurança. Embora o atacante use o **Pretexting** (fingir ser do suporte de TI), a tática principal para obter a ação é a pressão/ameaça.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Qual dos seguintes ataques explora a natureza humana em vez de vulnerabilidades de software ou hardware?",
  "opcoes": [
    "Injeção de SQL",
    "Estouro de buffer (Buffer overflow)",
    "Engenharia social",
    "Ataque de negação de serviço distribuído (DDoS)"
  ],
  "resposta": 2,
  "explicacao": "A **Engenharia Social** é a arte de manipular indivíduos para que realizem ações ou divulguem informações confidenciais. Este ataque explora falhas psicológicas e emocionais humanas, como confiança, curiosidade ou medo, sendo fundamentalmente diferente dos ataques que exploram vulnerabilidades técnicas em software ou hardware, como Injeção de SQL ou Estouro de Buffer.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "simnao",
  "texto": "Avalie as afirmações a seguir sobre o tema:",
  "afirmacoes": [
    "O Vírus de computador é um tipo de malware que, obrigatoriamente, se anexa a um arquivo hospedeiro e exige a execução desse arquivo para se replicar.",
    "Um Worm é um malware que precisa de um arquivo hospedeiro e da intervenção do usuário para se propagar em um sistema.",
    "O tipo de malware capaz de modificar ou excluir dados e cuja replicação ocorre apenas após a execução do arquivo legítimo ao qual está anexado é o Vírus."
  ],
  "respostas": [
    true,
    false,
    true
  ],
  "explicacao": "A replicação de um **Vírus** é dependente de um hospedeiro (anexar-se a um arquivo legítimo) e de uma ação do usuário (execução desse hospedeiro). A segunda afirmação está incorreta, pois a característica de ser autônomo (não precisar de hospedeiro ou intervenção para se propagar) é a principal distinção de um **Worm**.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Qual tipo de ator de ameaça é conhecido por invadir sistemas por razões ideológicas, políticas ou sociais, muitas vezes para protestar ou vazar informações?",
  "opcoes": [
    "Script kiddies",
    "Cibercriminosos",
    "Corretores de vulnerabilidades",
    "Hacktivistas"
  ],
  "resposta": 3,
  "explicacao": "Hacktivistas são indivíduos que combinam habilidades de hacking com ativismo político ou social. Sua motivação principal é ideológica, usando a invasão de sistemas para promover uma causa, protestar ou expor dados, diferentemente dos cibercriminosos, cuja motivação é tipicamente financeira.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Um hacker descobre uma falha de segurança em uma grande empresa. Ele não tem permissão para testar a rede, mas após explorar a vulnerabilidade, ele informa a empresa para que possam corrigi-la. Como esse hacker é classificado?",
  "opcoes": [
    "Hacker Patrocinado pelo Estado",
    "Hacker de Chapéu Cinza",
    "Hacker de Chapéu Branco",
    "Hacker de Chapéu Preto"
  ],
  "resposta": 1,
  "explicacao": "Um **Hacker de Chapéu Cinza** (Gray Hat) opera em uma área eticamente ambígua. Eles invadem ou exploram vulnerabilidades sem permissão, o que é ilegal, mas o fazem com a intenção de notificar e ajudar a corrigir a falha, sem intenção maliciosa, o que os difere dos Hackers de Chapéu Preto.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Qual ataque de rede explora o processo de estabelecimento de conexão TCP (aperto de mão de três vias) enviando um grande volume de pacotes SYN, mas nunca completando a conexão?",
  "opcoes": [
    "Ataque Smurf",
    "Sequestro de sessão TCP (Session Hijacking)",
    "Ataque de Inundação de SYN (SYN Flood)",
    "Envenenamento de ARP (ARP Poisoning)"
  ],
  "resposta": 2,
  "explicacao": "O **Ataque de Inundação de SYN (SYN Flood)** sobrecarrega os recursos do servidor ao explorar o handshake TCP de três vias. O atacante envia pacotes SYN e se recusa a enviar o ACK final, mantendo o servidor ocupado com conexões TCP semiabertas (SYN-RECEIVED), consumindo memória e limitando a capacidade de atender a conexões legítimas, o que caracteriza uma Negação de Serviço (DoS).",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Um ator de ameaça posiciona um ponto de acesso sem fio falso com o mesmo nome (SSID) da rede legítima de uma cafeteria para interceptar o tráfego dos usuários. Que tipo de ataque é esse?",
  "opcoes": [
    "Ponto de acesso (AP) invasor",
    "Bluejacking",
    "Ataque de negação de serviço (DoS) sem fio",
    "Ataque de AP gêmeo do mal (Evil Twin)"
  ],
  "resposta": 3,
  "explicacao": "O **Ataque de AP Gêmeo do Mal (Evil Twin)** é uma técnica que configura um ponto de acesso malicioso com o mesmo SSID e configurações de um AP legítimo (o 'gêmeo'). O objetivo é enganar os usuários para que se conectem ao AP falso, permitindo que o atacante intercepte e monitore o tráfego (ataque man-in-the-middle).",
  "dominio": "Comunicação de Redes sem fio"
},
{
  "tipo": "unica",
  "texto": "Qual das seguintes opções é uma técnica de segurança sem fio que tenta ocultar a existência da rede, impedindo que o ponto de acesso transmita seu nome (SSID)?",
  "opcoes": [
    "Ocultação do SSID",
    "Filtragem de endereços MAC",
    "Autenticação de sistema aberto",
    "WPA3"
  ],
  "resposta": 0,
  "explicacao": "A **Ocultação do SSID** desativa a transmissão do nome da rede nos quadros de sinalização (beacons) do Ponto de Acesso (AP). Isso exige que o usuário final insira o nome da rede manualmente para tentar se conectar, mas não é um método de segurança robusto, pois o SSID pode ser facilmente capturado por meio de ferramentas de análise de tráfego sem fio.",
  "dominio": "Comunicação de Redes sem fio"
},
{
  "tipo": "unica",
  "texto": "Um dispositivo de segurança é colocado em linha com o tráfego de rede e pode não apenas detectar, mas também bloquear ativamente o tráfego malicioso em tempo real. Como é chamado esse dispositivo?",
  "opcoes": [
    "Firewall de filtragem de pacotes",
    "Servidor proxy",
    "Sistema de Prevenção de Intrusão (IPS)",
    "Sistema de Detecção de Intrusão (IDS)"
  ],
  "resposta": 2,
  "explicacao": "Um **Sistema de Prevenção de Intrusão (IPS)** é um dispositivo de segurança que opera 'em linha' (in-line) com o tráfego da rede, permitindo-lhe não apenas identificar, mas também tomar medidas ativas e em tempo real para bloquear (descartar) o tráfego que corresponda a assinaturas de ataques conhecidos. Isso o diferencia de um **IDS**, que opera 'fora de banda' e apenas alerta.",
  "dominio": "Infraestrutura de segurança de rede"
},
{
  "tipo": "unica",
  "texto": "Qual protocolo é usado para traduzir nomes de domínio, como 'www.cisco.com', em endereços IP numéricos que os computadores usam para se comunicar?",
  "opcoes": [
    "SNMP (Protocolo Simples de Gerenciamento de Rede)",
    "ARP (Protocolo de Resolução de Endereços)",
    "DNS (Sistema de Nomes de Domínio)",
    "DHCP (Protocolo de Configuração Dinâmica de Host)"
  ],
  "resposta": 2,
  "explicacao": "O **DNS (Sistema de Nomes de Domínio)** é o protocolo responsável por traduzir nomes de domínio (que são fáceis de lembrar para humanos) em endereços IP numéricos que os computadores usam para se conectar e rotear dados na rede. Ele atua como o catálogo telefônico da Internet.",
  "dominio": "Atacando a Fundação"
},
{
  "tipo": "unica",
  "texto": "Um ataque no qual um ator de ameaça envia respostas ARP falsas para uma rede local, associando seu próprio endereço MAC ao endereço IP de outro dispositivo (como o gateway padrão), é conhecido como:",
  "opcoes": [
    "Falsificação de endereço IP (IP Spoofing)",
    "Ataque de Inundação de UDP (UDP Flood)",
    "Envenenamento de cache ARP (ARP Cache Poisoning)",
    "Falsificação de DHCP (DHCP Spoofing)"
  ],
  "resposta": 2,
  "explicacao": "O **Envenenamento de cache ARP** (ARP Cache Poisoning) é um ataque que visa corromper as tabelas ARP dos dispositivos em uma rede local (LAN). O atacante envia quadros de 'resposta ARP' falsos que associam seu próprio endereço MAC ao endereço IP do gateway padrão, redirecionando o tráfego e facilitando ataques Man-in-the-Middle (MitM).",
  "dominio": "Atacando a Fundação"
},
{
  "tipo": "unica",
  "texto": "A tecnologia NetFlow da Cisco é usada principalmente para qual finalidade?",
  "opcoes": [
    "Atribuir endereços IP dinamicamente aos hosts",
    "Sincronizar o tempo entre todos os dispositivos da rede",
    "Fornecer estatísticas sobre fluxos de pacotes IP para monitoramento e análise de tráfego",
    "Criptografar dados para criar túneis seguros através de redes públicas"
  ],
  "resposta": 2,
  "explicacao": "O **NetFlow** é uma tecnologia que coleta metadados sobre o fluxo de tráfego IP (incluindo endereços, portas e protocolos) e os exporta para um coletor. Sua finalidade principal é permitir o monitoramento detalhado, análise forense e detecção de anomalias na rede.",
  "dominio": "Infraestrutura de segurança de rede"
},
{
  "tipo": "unica",
  "texto": "Qual dos seguintes ataques explora a natureza humana em vez de vulnerabilidades de software ou hardware?",
  "opcoes": [
    "Injeção de SQL",
    "Estouro de buffer (Buffer overflow)",
    "Engenharia social",
    "Ataque de negação de serviço distribuído (DDoS)"
  ],
  "resposta": 2,
  "explicacao": "A **Engenharia Social** é a arte de manipular pessoas para que realizem ações ou divulguem informações confidenciais, explorando falhas psicológicas e emocionais humanas em vez de vulnerabilidades técnicas de software ou hardware.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "No contexto da segurança de rede, o que significa 'vetor de ataque'?",
  "opcoes": [
    "A motivação por trás de um ataque, como ganho financeiro ou espionagem.",
    "O impacto final de um ataque bem-sucedido, como perda de dados ou interrupção do serviço.",
    "O software usado para realizar um ataque, como um vírus ou worm.",
    "O caminho ou método que um ator de ameaça usa para obter acesso a um sistema ou rede."
  ],
  "resposta": 3,
  "explicacao": "O vetor de ataque é a rota ou o método pelo qual um agente de ameaça obtém acesso não autorizado a um sistema ou rede. Exemplos de vetores incluem e-mail de phishing, vulnerabilidades em software ou dispositivos de mídia física comprometidos, como uma unidade USB.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Qual das seguintes afirmações descreve corretamente a diferença entre um IDS (Sistema de Detecção de Intrusão) e um IPS (Sistema de Prevenção de Intrusão)?",
  "opcoes": [
    "IDS detecta ataques externos e IPS detecta ataques internos.",
    "IDS é usado para redes sem fio e IPS para redes cabeadas.",
    "IDS monitora e alerta, enquanto IPS pode monitorar, alertar e bloquear ativamente o ataque.",
    "IDS é baseado em hardware e IPS é baseado em software."
  ],
  "resposta": 2,
  "explicacao": "O IDS (Intrusion Detection System) é um sistema passivo que monitora o tráfego e gera alertas sobre atividades suspeitas. O IPS (Intrusion Prevention System) é um sistema ativo, implantado 'em linha', que monitora, alerta e é capaz de tomar medidas preventivas, como descartar pacotes ou encerrar conexões, bloqueando o ataque em tempo real.",
  "dominio": "Infraestrutura de segurança de rede"
},
{
  "tipo": "unica",
  "texto": "Um administrador de rede precisa copiar todo o tráfego de uma porta específica de um switch para outra porta, onde um analisador de rede está conectado para monitoramento. Qual recurso do switch ele deve usar?",
  "opcoes": [
    "NetFlow",
    "VLAN (Rede Local Virtual)",
    "Lista de Controle de Acesso (ACL)",
    "Espelhamento de portas (Port Mirroring)"
  ],
  "resposta": 3,
  "explicacao": "O recurso de Espelhamento de Portas, também conhecido como SPAN (Switched Port Analyzer), é projetado para duplicar o tráfego que passa por uma ou mais portas de origem e enviá-lo para uma porta de destino específica. Essa porta de destino geralmente conecta um analisador de rede para fins de monitoramento e solução de problemas.",
  "dominio": "Protegendo Redes"
},
{
  "tipo": "unica",
  "texto": "O que o componente 'Accounting' (Contabilidade) da estrutura AAA (Autenticação, Autorização e Contabilidade) faz?",
  "opcoes": [
    "Verifica a identidade de um usuário, confirmando quem ele é.",
    "Determina quais recursos um usuário autenticado pode acessar.",
    "Criptografa as senhas dos usuários para armazenamento seguro.",
    "Registra as ações de um usuário, como os recursos acessados e o tempo de conexão."
  ],
  "resposta": 3,
  "explicacao": "O componente Accounting (Contabilidade) é responsável por rastrear o uso dos recursos de rede por um usuário. Isso inclui registrar o que o usuário acessou, a hora de login e logout, e a quantidade de dados transferidos. Autenticação é 'quem é você', Autorização é 'o que você pode fazer' e Contabilidade é 'o que você fez'.",
  "dominio": "Infraestrutura de segurança de rede"
},
{
  "tipo": "unica",
  "texto": "Qual campo no cabeçalho de um pacote IPv4 é usado para limitar a vida útil do pacote, sendo decrementado a cada salto (roteador) que ele atravessa?",
  "opcoes": [
    "Deslocamento do fragmento (Fragment Offset)",
    "Tempo de Vida (Time to Live - TTL)",
    "Protocolo (Protocol)",
    "Soma de verificação do cabeçalho (Header Checksum)"
  ],
  "resposta": 1,
  "explicacao": "O campo **Tempo de Vida (TTL)** é um valor de 8 bits no cabeçalho IPv4 que é decrementado em um a cada roteador (salto) que o pacote atravessa. Quando o valor do TTL atinge zero, o roteador descarta o pacote. Esse mecanismo evita que os pacotes fiquem em loops de roteamento infinitos, consumindo largura de banda da rede indefinidamente.",
  "dominio": "Protegendo Redes"
},
{
  "tipo": "unica",
  "texto": "Um ataque que utiliza um grande número de computadores comprometidos (uma botnet) para sobrecarregar um alvo com tráfego de rede é conhecido como:",
  "opcoes": [
    "Ataque de Negação de Serviço Distribuído (DDoS)",
    "Ataque de Negação de Serviço (DoS)",
    "Ataque Homem no Meio (MitM)",
    "Ataque Smurf"
  ],
  "resposta": 0,
  "explicacao": "Um **Ataque de Negação de Serviço Distribuído (DDoS)** é caracterizado pelo uso de múltiplos sistemas comprometidos (uma botnet) que atacam simultaneamente um único alvo. O prefixo 'Distribuído' indica que o volume massivo de tráfego é coordenado a partir de diversas fontes, com o objetivo de sobrecarregar e indisponibilizar o serviço do alvo.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Um funcionário digita acidentalmente o endereço de um site popular com um erro de digitação e é redirecionado para um site malicioso que se parece com o original. Que tipo de ataque é este?",
  "opcoes": [
    "Pharming",
    "Phishing",
    "Typosquatting",
    "Redirecionamento de URL"
  ],
  "resposta": 2,
  "explicacao": "O **Typosquatting**, também conhecido como sequestro de URL, é um ataque que explora erros de digitação comuns de nomes de domínio (URLs). Os invasores registram domínios com esses erros de digitação para atrair usuários desavisados para sites maliciosos que se parecem com o site legítimo, geralmente para roubar credenciais.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "As quatro fases de mitigação de um ataque de worm são contenção, inoculação, quarentena e tratamento. O que ocorre na fase de 'contenção'?",
  "opcoes": [
    "Limitar a propagação da infecção para áreas não afetadas da rede.",
    "Remover o worm de todos os sistemas infectados.",
    "Verificar se os sistemas limpos não foram reinfectados antes de reconectá-los.",
    "Aplicar patches e correções em todos os sistemas para prevenir a reinfecção."
  ],
  "resposta": 0,
  "explicacao": "A fase de **contenção** é a primeira etapa na mitigação de um worm e tem como objetivo principal isolar os sistemas infectados e segmentar a rede para impedir que o worm se espalhe ainda mais para áreas não afetadas. Isso limita o escopo do ataque, permitindo as etapas subsequentes de limpeza.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Qual é a principal desvantagem de usar um Sistema de Detecção de Intrusão (IDS) em comparação com um Sistema de Prevenção de Intrusão (IPS)?",
  "opcoes": [
    "Ele introduz latência significativa na rede.",
    "Ele não pode parar o pacote malicioso que acionou o alerta.",
    "Requer a instalação de software em cada host da rede.",
    "Ele gera um número muito maior de falsos positivos."
  ],
  "resposta": 1,
  "explicacao": "A principal desvantagem do IDS é que ele opera passivamente, ou seja, detecta e alerta a ocorrência de uma intrusão, mas não tem a capacidade de tomar medidas ativas, como bloquear ou descartar o tráfego em tempo real. O pacote malicioso geralmente já alcançou o alvo antes que o alerta seja gerado.",
  "dominio": "Infraestrutura de segurança de rede"
},
{
  "tipo": "unica",
  "texto": "Que tipo de firewall mantém o controle do estado das conexões de rede (como TCP streams) e toma decisões com base no contexto da conversa, não apenas em pacotes individuais?",
  "opcoes": [
    "Firewall de gateway de aplicativo (Proxy)",
    "Firewall com monitoração de estado (Stateful)",
    "Firewall de filtragem de pacotes (sem estado)",
    "Firewall baseado em host"
  ],
  "resposta": 1,
  "explicacao": "Um **Firewall com Monitoração de Estado (Stateful)** monitora o estado de todas as conexões ativas. Ele usa uma tabela de estados para determinar se um pacote pertence a uma sessão estabelecida. Isso permite que ele julgue o tráfego não apenas com base nas regras estáticas, mas também no contexto da comunicação, permitindo automaticamente o tráfego de resposta legítimo que foi iniciado internamente.",
  "dominio": "Infraestrutura de segurança de rede"
},
{
  "tipo": "unica",
  "texto": "Qual é o objetivo de um ataque 'Bluesnarfing'?",
  "opcoes": [
    "Sobrecarrregar um dispositivo com solicitações Bluetooth para torná-lo inutilizável.",
    "Criar um ponto de acesso Wi-Fi falso para interceptar o tráfego de rede.",
    "Enviar mensagens não solicitadas ou imagens para um dispositivo Bluetooth próximo.",
    "Copiar informações, como contatos e e-mails, de um dispositivo alvo através de uma conexão Bluetooth vulnerável."
  ],
  "resposta": 3,
  "explicacao": "O **Bluesnarfing** é um ataque que explora uma vulnerabilidade no protocolo Bluetooth para acessar e extrair dados sigilosos, como listas de contatos, e-mails, mensagens de texto e arquivos, de um dispositivo alvo sem o consentimento ou conhecimento do usuário.",
  "dominio": "Comunicação de Redes sem fio"
},
{
  "tipo": "unica",
  "texto": "O protocolo NTP (Network Time Protocol) é usado para sincronizar a hora em dispositivos de rede. O que indica um número de 'stratum' mais baixo (por exemplo, stratum 1)?",
  "opcoes": [
    "Que o dispositivo está menos preciso e mais longe da fonte de tempo original.",
    "Que o dispositivo não está sincronizado com a rede.",
    "Que o dispositivo está usando uma versão mais antiga do protocolo NTP.",
    "Que o dispositivo está mais próximo da fonte de tempo autorizada (como um relógio atômico)."
  ],
  "resposta": 3,
  "explicacao": "O nível **stratum** define a distância de um dispositivo até a fonte de tempo autorizada e original (como um relógio atômico ou GPS). Quanto menor o número de stratum, mais perto e mais preciso o dispositivo está em relação à fonte primária. O stratum 1 é o servidor NTP primário que está diretamente conectado à fonte de tempo autorizada (stratum 0).",
  "dominio": "Protegendo Redes"
},
{
  "tipo": "unica",
  "texto": "O que é um 'domínio de usuário' no contexto de segurança da informação?",
  "opcoes": [
    "O conjunto de políticas e procedimentos de segurança de uma organização.",
    "Qualquer pessoa com acesso ao sistema de informações, incluindo funcionários, clientes e parceiros.",
    "As instalações físicas, como escritórios e data centers, usadas por uma empresa.",
    "Todos os computadores e dispositivos conectados à rede de uma empresa."
  ],
  "resposta": 1,
  "explicacao": "O **domínio de usuário** refere-se a todos os indivíduos que interagem com o sistema de informação da organização, como funcionários, clientes, fornecedores e parceiros. Este domínio é frequentemente considerado o elo mais fraco da segurança cibernética devido ao risco de engenharia social, erros e negligência, sendo essencial focar em conscientização e treinamento.",
  "dominio": "Ameaças, Vulnerabilidades e Ataques à Segurança Cibernética"
},
{
  "tipo": "unica",
  "texto": "Um criminoso observa por cima do ombro de alguém em um caixa eletrônico para obter o PIN. Como é chamado esse ataque simples, porém eficaz?",
  "opcoes": [
    "Tailgating",
    "Surf de Ombro (Shoulder Surfing)",
    "Representação (Impersonation)",
    "Mergulho no lixo (Dumpster Diving)"
  ],
  "resposta": 1,
  "explicacao": "O **Surf de Ombro (Shoulder Surfing)** é uma forma de ataque de engenharia social onde o invasor observa fisicamente as vítimas digitarem informações confidenciais, como senhas, PINs ou dados de cartões de crédito. É um método de coleta de informações não técnico, mas altamente eficaz.",
  "dominio": "Atacando a Fundação"
},
{
  "tipo": "unica",
  "texto": "Um ataque de 'injeção' explora a validação inadequada de dados inseridos pelo usuário. Se um site usa um banco de dados SQL, que tipo de ataque de injeção é uma ameaça comum?",
  "opcoes": [
    "Cross-Site Scripting (XSS)",
    "Injeção de XML",
    "Injeção de SQL",
    "Injeção de LDAP"
  ],
  "resposta": 2,
  "explicacao": "A **Injeção de SQL** é um ataque que insere ou 'injeta' comandos de consulta SQL maliciosos em um campo de entrada da aplicação web. Isso acontece quando a aplicação não valida ou sanitiza corretamente os dados inseridos pelo usuário, permitindo que o invasor manipule o banco de dados, podendo visualizar, modificar ou excluir dados.",
  "dominio": "Atacando o que fazemos"
}

  


];
