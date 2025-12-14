#!/usr/bin/env bash


open_redir_parameters=(
	'?next='
	'?url='
	'?target='
	'?rurl='
	'?dest='
	'?destination='
	'?redir='
	'?redirect_uri='
	'?redirect_url='
	'?redirect='
	'/redirect/'
	'/cgi-bin/redirect.cgi?'
	'/out/'
	'/out?'
	'?view='
	'/login?to='
	'?image_url='
	'?go='
	'?return='
	'?returnTo='
	'?return_to='
	'?checkout_url='
	'?continue='
	'?return_path='
	'inurl:wp-content/uploads/ intitle:logs'
)

rce_parameters=(
	'?cmd='
	'?exec='
	'?command='
	'?execute'
	'?ping='
	'?query='
	'?jump='
	'?code='
	'?reg='
	'?do='
	'?func='
	'?arg='
	'?option='
	'?load='
	'?process='
	'?step='
	'?read='
	'?function='
	'?req='
	'?feature='
	'?exe='
	'?module='
	'?payload='
	'?run='
	'?print='

)

lfi_parameters=(
	'?cat='
	'?dir='
	'?action='
	'?board='
	'?date='
	'?detail='
	'?file='
	'?download='
	'?path='
	'?folder='
	'?prefix='
	'?include='
	'?page='
	'?inc='
	'?locate='
	'?show='
	'?doc='
	'?site='
	'?type='
	'?view='
	'?content='
	'?document='
	'?layout='
	'?mod='
	'?conf='

)


# Banner CVE-Hunters
show_banner() {
	echo -e "\033[38;5;198m"
	echo "  ██████╗██╗   ██╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ███████╗"
	echo " ██╔════╝██║   ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝"
	echo " ██║     ██║   ██║█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝███████╗"
	echo " ██║     ╚██╗ ██╔╝██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗╚════██║"
	echo " ╚██████╗ ╚████╔╝ ███████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║███████║"
	echo "  ╚═════╝  ╚═══╝  ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝"
	echo -e "\033[38;5;81m                          Reconhecimento Automatizado de Vulnerabilidades\033[m"
	echo -e "\033[38;5;228m                                    CVE-Hunters Team | 2025\033[m\n"
}

show_help() {
	show_banner
	echo -e "\n\tUso: \033[38;5;208m./subs.sh \033[38;5;198m[ -d dominio ]\033[38;5;81m [ -w wordlist.txt ]\033[38;5;228m [ -g GitHub-API_KEY ] [ -s Shodan-API_KEY ]\033[m [ -q ] [ -f ]"
	echo -e "\n\t-d  | (obrigatório) : Seu \033[38;5;198malvo\033[m"
	echo -e "\t-w  | (obrigatório) : Caminho para sua \033[38;5;81mwordlist\033[m"
	echo -e "\t-q  | (opcional)    : Modo silencioso"
	echo -e "\t-o  | (opcional)    : Pasta de saída. Padrão é a pasta do script"
	echo -e "\t-f  | (opcional)    : Ativar modo Fuzzing"
	echo -e "\n\t\033[38;5;228m[!] API_KEYS. Não passar suas chaves API significa que scans que precisam delas serão pulados\033[m"
	echo -e "\t-g  | (opcional)    : Sua chave \033[38;5;228mAPI do GitHub\033[m"
	echo -e "\t-s  | (opcional)    : Sua chave \033[38;5;228mAPI do Shodan\033[38;5;198m (Requer API Premium)\033[m"
}

# ╔═══════════════════════════════════════════════════════════════════════╗
# ║                    SISTEMA DE CHECKPOINTS E PROGRESSO                 ║
# ╚═══════════════════════════════════════════════════════════════════════╝

# Lista de todas as etapas do pipeline
PIPELINE_STEPS=(
	"asn_enum"
	"subdomain_enum"
	"organize_domains"
	"subdomain_takeover"
	"dns_lookup"
	"check_active"
	"waf_detect"
	"favicon_analysis"
	"directory_fuzzing"
	"cred_stuff"
	"google_hacking"
	"github_dorks"
	"screenshots"
	"port_scanning"
	"link_discovery"
	"endpoints_enum"
	"vulnerability_scan"
)

# Inicializa arquivo de checkpoint
init_checkpoint() {
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	if [ ! -f "$checkpoint_file" ]; then
		echo "# CVE-Hunters Checkpoint File" > "$checkpoint_file"
		echo "# Scan iniciado em: $(date '+%Y-%m-%d %H:%M:%S')" >> "$checkpoint_file"
		echo "# Alvo: $domain" >> "$checkpoint_file"
		echo "" >> "$checkpoint_file"
	fi
}

# Verifica se uma etapa já foi completada
check_step() {
	local step_name="$1"
	local checkpoint_file="$OUTFOLDER/.checkpoint"

	if [ ! -f "$checkpoint_file" ]; then
		return 1  # Etapa não foi completa
	fi

	if grep -q "^${step_name}:completed:" "$checkpoint_file" 2>/dev/null; then
		return 0  # Etapa já foi completa
	else
		return 1  # Etapa não foi completa
	fi
}

# Marca uma etapa como completa
mark_step_complete() {
	local step_name="$1"
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

	# Remove entrada antiga se existir
	sed -i "/^${step_name}:/d" "$checkpoint_file" 2>/dev/null

	# Adiciona nova entrada
	echo "${step_name}:completed:${timestamp}" >> "$checkpoint_file"

	# Atualiza progresso
	show_progress
}

# Mostra progresso atual
show_progress() {
	if [ "$QUIET" == "True" ]; then
		return
	fi

	local checkpoint_file="$OUTFOLDER/.checkpoint"
	local total_steps=${#PIPELINE_STEPS[@]}
	local completed_steps=0

	if [ -f "$checkpoint_file" ]; then
		completed_steps=$(grep -c ":completed:" "$checkpoint_file" 2>/dev/null || echo 0)
	fi

	# Remove quebras de linha e garante valores numéricos válidos
	completed_steps=$(echo "$completed_steps" | tr -d '\n\r' | sed 's/[^0-9]//g')
	[ -z "$completed_steps" ] && completed_steps=0

	total_steps=$(echo "$total_steps" | tr -d '\n\r' | sed 's/[^0-9]//g')
	# Evita divisão por zero
	[ -z "$total_steps" ] || [ "$total_steps" -eq 0 ] 2>/dev/null && total_steps=17

	local percentage=$((completed_steps * 100 / total_steps))

	echo -e "\n\033[38;5;81m┌─────────────────────────────────────────────┐\033[m"
	echo -e "\033[38;5;81m│\033[m  \033[38;5;198m📊 Progresso:\033[m $completed_steps/$total_steps etapas (\033[38;5;148m${percentage}%\033[m)  \033[38;5;81m│\033[m"
	echo -e "\033[38;5;81m└─────────────────────────────────────────────┘\033[m\n"
}

# Faz merge inteligente de resultados (adiciona apenas novos)
merge_results() {
	local new_file="$1"
	local target_file="$2"

	if [ ! -f "$new_file" ]; then
		return
	fi

	if [ ! -f "$target_file" ]; then
		# Se arquivo alvo não existe, apenas move o novo
		mv "$new_file" "$target_file"
	else
		# Faz merge usando anew (adiciona apenas linhas únicas)
		if command -v anew >/dev/null 2>&1; then
			cat "$new_file" | anew "$target_file" > /dev/null
			rm -f "$new_file"
		else
			# Fallback: usa sort -u se anew não estiver disponível
			cat "$new_file" "$target_file" | sort -u > "${target_file}.tmp"
			mv "${target_file}.tmp" "$target_file"
			rm -f "$new_file"
		fi
	fi
}

# Wrapper para executar etapas com checkpoint
run_step() {
	local step_name="$1"
	local step_function="$2"
	shift 2
	local step_args="$@"

	# Verifica se etapa já foi completa
	if check_step "$step_name"; then
		if [ "$QUIET" != "True" ]; then
			echo -e "\033[38;5;228m[⏭️ ] Etapa '$step_name' já completa, pulando...\033[m"
		fi
		return 0
	fi

	# Marca como em progresso
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
	sed -i "/^${step_name}:/d" "$checkpoint_file" 2>/dev/null
	echo "${step_name}:in_progress:${timestamp}" >> "$checkpoint_file"

	# Executa a função
	$step_function $step_args

	# Marca como completa
	mark_step_complete "$step_name"
}


grepVuln() {
    local -n arr=$1  # Cria uma referência para o array passado pelo nome
    local file=$3    # O arquivo de entrada

    for pattern in "${arr[@]}"; do
        if [ "$QUIET" != "True" ]; then
            grep "$pattern" "$file" | tee -a "$3.found"
        else
            grep "$pattern" "$file" >> "$3.found"
        fi
    done
}
# Uso: grepVuln lfi_parameters "arquivo_alvo" output.txt


wafDetect() {
	if [ "$(cat $1 | wc -l)" -ge "1" ] && [ "$1" != "" ]; then
		if [ "$QUIET" == "True" ];then
			echo -e -n "\033[38;5;81m[+] Detectando WAF 🔎\033[m"
			wafw00f -i $1 -a -o $OUTFOLDER/subdomains/waf.txt > /dev/null
			echo " ✅"
		else
			printf "\n\033[38;5;198m"
		printf "\t╔════════════════════════════════════════════════╗\n"
		printf "\t║  🛡️  DETECÇÃO WAF - Identificando Firewalls  ║\n"
		printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			wafw00f -i $1 -a -o $OUTFOLDER/subdomains/waf.txt
		fi
	fi
}


organizeDomains() {
	domains="$1"
	LDOUT="$2/level-domains.txt"
	if [ -r "$domains" ] && [ "$(cat $domains | wc -l)" -ge "1" ]; then
		echo -e "\033[38;5;198m[+] Organizando seus domínios 😊\033[m"
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[38;5;148m[+] Encontrando domínios de 2º nível...\033[m"
		fi
		echo -e "[+] Encontrando domínios de 2º nível..." >>  $LDOUT
		if [ "$QUIET" != "True" ]; then
			cat $DOMAINS | grep -P '^(?:[a-z0-9]+\.){1}[^.]*$' | tee -a $LDOUT
		else
			cat $DOMAINS | grep -P '^(?:[a-z0-9]+\.){1}[^.]*$' >> $LDOUT
		fi
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[38;5;148m[+] Encontrando domínios de 3º nível...\033[m"
		fi
		echo "[+] Encontrando domínios de 3º nível..." >> $LDOUT
		if [ "$QUIET" != "True" ]; then
			cat $DOMAINS | grep -P '^(?:[a-z0-9]+\.){2}[^.]*$' | tee -a $LDOUT
		else
			cat $DOMAINS | grep -P '^(?:[a-z0-9]+\.){2}[^.]*$' >> $LDOUT
		fi
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[38;5;148m[+] Encontrando domínios de 4º nível ou superior\033[m"
		fi
		echo "[+] Encontrando domínios de 4º nível ou superior" >> $LDOUT
		if [ "$QUIET" != "True" ]; then
			cat $DOMAINS | grep -P '^(?:[a-z0-9]+\.){3,}[^.]*$' | tee -a $LDOUT
		else
			cat $DOMAINS | grep -P '^(?:[a-z0-9]+\.){3,}[^.]*$' >> $LDOUT
		fi
		echo -e "\033[38;5;148m[!] Concluído. Saída salva em $LDOUT\033[m"
	fi
}


asnEnum() {
	subdomain="$1"
	output_folder="$2"
	[[ ! -d $output_folder ]] && mkdir $output_folder 2>/dev/null
	org="$(echo $domain | cut -d '.' -f1)"

	# Remove arquivo temporário se existir
	rm -f $output_folder/$org.txt.new

	if [ "$QUIET" != "True" ]; then
		printf "\n\033[38;5;198m"
		printf "\t╔════════════════════════════════════════════════╗\n"
		printf "\t║  🔍  ENUMERAÇÃO ASN - Mapeando Redes  🔍     ║\n"
		printf "\t╚════════════════════════════════════════════════╝\n"
		printf "\033[m\n"
		ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.25 echo $org | metabigor net --org -o $output_folder/$org.txt.new 2>/dev/null
	else
		echo -e -n "\n\033[38;5;81m[+] Enumeração ASN 🔎\033[m"
		ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.25 echo $org | metabigor net --org >> $output_folder/$org.txt.new 2>/dev/null
		echo " ✅"
	fi

	if [[ -e $output_folder/$org.txt.new ]]; then
		sort -u $output_folder/$org.txt.new -o $output_folder/$org.txt.new

		# Merge inteligente com arquivo existente
		if [ -f "$output_folder/$org.txt" ]; then
			cp $output_folder/$org.txt $output_folder/$org.txt.backup
			merge_results "$output_folder/$org.txt.new" "$output_folder/$org.txt"

			old_count=$(cat $output_folder/$org.txt.backup | wc -l)
			new_count=$(cat $output_folder/$org.txt | wc -l)
			added=$((new_count - old_count))

			if [ $added -gt 0 ]; then
				echo -e "\n\033[38;5;148m[+] Adicionados \033[38;5;198m$added\033[38;5;148m novos ASNs (total: \033[38;5;198m$new_count\033[38;5;148m)\033[m"
			else
				echo -e "\n\033[38;5;228m[!] Nenhum ASN novo (total: \033[38;5;198m$new_count\033[38;5;148m)\033[m"
			fi
		else
			mv $output_folder/$org.txt.new $output_folder/$org.txt
			asns="$(cat $output_folder/$org.txt | wc -l)"
			echo -e "\n\033[38;5;148m[!] Encontrados \033[38;5;198m$asns\033[38;5;148m ASNs\033[m"
		fi
	else
		echo -e "\n\033[38;5;148m[!] Encontrados \033[38;5;198m0\033[38;5;148m ASNs\033[m"
	fi
}


checkActive() {
	subdomains="$1"
	output_folder="$2"
	if [ "$(cat $subdomains | wc -l)" -ge "1" ]; then
		# Remove arquivo temporário se existir
		rm -f $output_folder/alive.txt.new

		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;148m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  ✅  TESTANDO DOMÍNIOS - Verificando Ativos  ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			echo -e "\033[38;5;208m[!] LIVE FEED: Novos domínios ativos aparecerão abaixo em tempo real!\033[m"
			cat $subdomains | httprobe | while read line; do echo -e "\033[38;5;46m[NEW] $line\033[m"; echo "$line" >> $output_folder/alive.txt.new; done
			cat $subdomains | httpx --silent --threads 300 | while read line; do echo -e "\033[38;5;46m[NEW] $line\033[m"; echo "$line" >> $output_folder/alive.txt.new; done
		else
			echo -e "\n\033[38;5;81m[+] Domínios Ativos 🔎\033[m"
			cat $subdomains | httprobe >> $output_folder/alive.txt.new
			cat $subdomains | httpx --silent --threads 300 >> $output_folder/alive.txt.new
		fi

		# Limpa e remove duplicatas dos novos resultados
		sort -u $output_folder/alive.txt.new -o $output_folder/alive.txt.new

		# Merge inteligente com arquivo existente
		if [ -f "$output_folder/alive.txt" ]; then
			cp $output_folder/alive.txt $output_folder/alive.txt.backup
			merge_results "$output_folder/alive.txt.new" "$output_folder/alive.txt"

			old_count=$(cat $output_folder/alive.txt.backup | wc -l)
			new_count=$(cat $output_folder/alive.txt | wc -l)
			added=$((new_count - old_count))

			if [ $added -gt 0 ]; then
				echo -e "\033[38;5;148m[+] Adicionados \033[38;5;198m$added\033[38;5;148m novos domínios ativos (total: \033[38;5;198m$new_count\033[38;5;148m)\033[m"
			else
				echo -e "\033[38;5;228m[!] Nenhum domínio novo ativo (total: \033[38;5;198m$new_count\033[38;5;148m)\033[m"
			fi
		else
			mv $output_folder/alive.txt.new $output_folder/alive.txt
			count=$(cat $output_folder/alive.txt | wc -l)
			echo -e "\033[38;5;148m[!] Encontrados \033[38;5;198m$count\033[38;5;148m domínios ativos\033[m"
		fi
	fi
}


subdomainEnumeration() {
	target="$1"
	output_folder="$2"
	if [ -n "$target" ] && [ -n "$output_folder" ]; then
		[[ ! -d $output_folder ]] && mkdir $output_folder 2>/dev/null
		[[ ! -d $output_folder/knockpy/ ]] && mkdir $output_folder/knockpy/ 2>/dev/null

		# Remove arquivo temporário se existir de run anterior
		rm -f $output_folder/subdomains.txt.new

		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;81m"
			printf "\t╔═══════════════════════════════════════════════════╗\n"
			printf "\t║  🎯  ENUMERAÇÃO DE SUBDOMÍNIOS - Multi-Tool  🎯  ║\n"
			printf "\t╚═══════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			echo -e "\033[38;5;228m[!] Todos os subdomínios serão salvos em \033[38;5;198m$output_folder/subdomains.txt\033[m"
			echo -e "\033[38;5;81m>>>\033[38;5;141m Executando assetfinder 🔍\033[m"
			assetfinder $target | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/assetfinder $target | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando subfinder 🔍\033[m"
			subfinder -d $target -all -silent | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/subfinder --silent -d $target | tee -a $output_folder/subdomains.txt.new
			#echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando amass 🔍\033[m"
			#amass enum --passive -d $target | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/amass enum --passive -d $target | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando findomain 🔍\033[m"
			findomain -q --target $target | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/findomain -q --target $target | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando SubDomainizer 🔍\033[m"
			sublist3r -d $target -o $SCRIPTPATH/sublist3r-$domain.txt
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && cat $SCRIPTPATH/sublist3r-$domain.txt >> $output_folder/subdomains.txt.new
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && rm $SCRIPTPATH/sublist3r-$domain.txt
			knockpy -d $target -w $wordlist --save $output_folder/knockpy/ -t 5
			if [ "$GHAPIKEY" != "False" ]; then
				echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando Github-Subdomains 🔍\033[m"
				python3 $SCRIPTPATH/tools/github-search/github-subdomains.py -t $GHAPIKEY -d $target | tee -a $output_folder/subdomains.txt.new
			fi
		else
			echo -e "\n\033[38;5;81m[+] Enumeração de Subdomínios 🔎\033[m"
			echo -e "\033[38;5;228m[!] Todos os subdomínios serão salvos em \033[38;5;198m$output_folder/subdomains.txt\033[m"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando assetfinder 🔍\033[m"
			assetfinder $target >> $output_folder/subdomains.txt.new || $GOPATH/bin/assetfinder $target >> $output_folder/subdomains.txt.new
			echo " ✅"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando subfinder 🔍\033[m"
			subfinder --silent -d $target >> $output_folder/subdomains.txt.new || $GOPATH/bin/subfinder --silent -d $target >> $output_folder/subdomains.txt.new
			echo " ✅"
			#echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando amass 🔍\033[m"
			#amass enum --passive -d $target >> $output_folder/subdomains.txt.new || $GOPATH/bin/amass enum --passive -d $target >> $output_folder/subdomains.txt.new
			#echo " ✅"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando findomain 🔍\033[m"
			findomain -q --target $target >> $output_folder/subdomains.txt.new || $GOPATH/bin/findomain -q --target $target >> $output_folder/subdomains.txt.new
			echo " ✅"
			echo -e -n "\n\033[38;5;81m>>>\033[38;5;141m Executando sublist3r 🔍\033[m"
			sublist3r -d $target -o $SCRIPTPATH/sublist3r-$domain.txt > $SCRIPTPATH/temp.txt
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && cat $SCRIPTPATH/sublist3r-$domain.txt >> $output_folder/subdomains.txt.new
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && rm $SCRIPTPATH/sublist3r-$domain.txt
			[ -f "$SCRIPTPATH/temp.txt" ] && rm $SCRIPTPATH/temp.txt
			echo " ✅"
			echo -e -n "\n\033[38;5;81m>>>\033[38;5;141m Executando Knockpy 🔍\033[m"
			knockpy -d $target -w $wordlist -o $output_folder/knockpy/ -t 5 > $SCRIPTPATH/knocktemp
			[ -f "$SCRIPTPATH/knocktemp" ] && rm $SCRIPTPATH/knocktemp
			echo " ✅"
			if [ "$GHAPIKEY" != "False" ]; then
				echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando Github-Subdomains 🔍\033[m"
				python3 $SCRIPTPATH/tools/github-search/github-subdomains.py -t $GHAPIKEY -d $target >> $output_folder/subdomains.txt.new
				echo " ✅"
			fi
		fi
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && cat $SCRIPTPATH/SubDomainizer$domain.txt >> $output_folder/subdomains.txt.new
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && rm $SCRIPTPATH/SubDomainizer$domain.txt
		#for a in $(ls $output_folder/knockpy/*); do
		#	python3 $SCRIPTPATH/scripts/knocktofile.py -f $a -o $SCRIPTPATH/knock.txt
		#done
		#cat $SCRIPTPATH/knock.txt >> $output_folder/subdomains.txt.new
		#rm $SCRIPTPATH/knock.txt

		# Limpa resultados novos (remove wildcards e erros)
		cat $output_folder/subdomains.txt.new 2>/dev/null | grep -v "\*" | grep -v "error occurred" | sort -u > $SCRIPTPATH/temporary_clean.txt

		# Faz merge inteligente com resultados anteriores (se existirem)
		if [ -f "$output_folder/subdomains.txt" ]; then
			# Backup do arquivo antigo
			cp $output_folder/subdomains.txt $output_folder/subdomains.txt.backup

			# Merge usando anew ou sort -u
			merge_results "$SCRIPTPATH/temporary_clean.txt" "$output_folder/subdomains.txt"

			# Conta quantos novos foram adicionados
			old_count=$(cat $output_folder/subdomains.txt.backup | wc -l)
			new_count=$(cat $output_folder/subdomains.txt | wc -l)
			added=$((new_count - old_count))

			if [ $added -gt 0 ]; then
				echo -e "\n\033[38;5;148m[+] Adicionados \033[38;5;198m$added\033[38;5;148m novos subdomínios (total: \033[38;5;198m$new_count\033[38;5;148m)\033[m"
			else
				echo -e "\n\033[38;5;228m[!] Nenhum subdomínio novo encontrado (total: \033[38;5;198m$new_count\033[38;5;148m)\033[m"
			fi
		else
			# Primeira vez, apenas move o arquivo limpo
			mv $SCRIPTPATH/temporary_clean.txt $output_folder/subdomains.txt
			uniq="$(cat $output_folder/subdomains.txt | wc -l)"
			echo -e "\n\033[38;5;148m[!] Encontrados \033[38;5;198m$uniq\033[38;5;148m subdomínios\033[m"
		fi

		# Remove arquivos temporários
		rm -f $output_folder/subdomains.txt.new $SCRIPTPATH/temporary_clean.txt
	fi
}


subdomainTakeover() {
	list="$1"
	output_folder="$2"
	if [ "$(cat $list | wc -l)" -ge "1" ]; then
		[[ ! -d $output_folder ]] && mkdir $output_folder
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;208m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  ⚠️  SUBDOMAIN TAKEOVER - Caça a Vulneráveis ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
		else
			echo -e "\n\033[38;5;81m[+] Subdomain Takeover 🔎\033[m"
		fi
		subjack -w $list -t 100 -timeout 30 -o $output_folder/takeover.txt -ssl || $GOPATH/bin/subjack -w $list -t 100 -timeout 30 -o $output_folder/takeover.txt -ssl
		if [ -f "$output_folder/takeover.txt" ]; then
			stofound="$(cat $output_folder/takeover.txt | wc -l)"
			echo -e "\033[38;5;148m[+] $stofound domínios vulneráveis foram encontrados\033[m"
		else
			echo -e "\033[38;5;198m[-] Nenhum domínio vulnerável a Subdomain Takeover\033[m"
		fi
	fi
}


dnsLookup() {
	domains="$1"
	output_folder="$2"
	[[ ! -d $output_folder/DNS ]] && mkdir $output_folder/DNS
	if [ "$(cat $domains | wc -l)" -ge "1" ]; then
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;141m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  🌐  DNS LOOKUP - Resolução e Enumeração  🌐  ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			echo -e "\033[38;5;81m>>>\033[38;5;141m Descobrindo IPs 🔍\033[38;5;148m"
			dnsx --silent -l $domains -resp -o $output_folder/DNS/dns.txt || $GOPATH/bin/dnsx -l $DOMAINS -resp -o $output_folder/DNS/dns.txt
			echo -e "\033[m"
			echo -e "\033[38;5;81m>>>\033[38;5;141m Enumeração DNS 🔍\033[m"
			dnsrecon -d $domain -D $wordlist | tee -a $output_folder/DNS/dnsrecon.txt
			dnsenum $domain -f $wordlist -o $output_folder/DNS/dnsenum.xml
		else
			echo -e "\n\033[38;5;81m[+] DNS Lookup 🔎\033[m"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Descobrindo IPs 🔍\033[m"
			dnsx --silent -l $domains -resp -o $output_folder/DNS/dns.txt > $SCRIPTPATH/temp || $GOPATH/bin/dnsx --silent -l $domains -resp -o $output_folder/DNS/dns.txt > $SCRIPTPATH/temp
			rm $SCRIPTPATH/temp
			echo " ✅"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Enumeração DNS 🔍\033[m"
			dnsrecon -d $domain -D $wordlist >> $output_folder/DNS/dnsrecon.txt 2>/dev/null > $SCRIPTPATH/temp1
			rm $SCRIPTPATH/temp1
			dnsenum $domain -f $wordlist -o $output_folder/DNS/dnsenum.xml 2>/dev/null > $SCRIPTPATH/temp2
			rm $SCRIPTPATH/temp2
			echo " ✅"
		fi
		cat $output_folder/DNS/dns.txt | awk '{print $2}' | tr -d "[]" >> $output_folder/DNS/ip_only.txt
		if [ -e $output_folder/DNS/ip_only.txt ]; then
			ipfound="$(cat $output_folder/DNS/ip_only.txt | wc -l)"
			echo -e "\033[38;5;198m[+] Encontrados \033[38;5;198m$ipfound\033[38;5;148m IPs\033[m"
		fi
		[ -f "$SCRIPTPATH/$domain\_ips.txt" ] && rm $SCRIPTPATH/$domain\_ips.txt
	fi
}


favAnalysis() {
	alive_domains="$1"
	output_folder="$2"
	FAVOUT="$output_folder/favfreak"
	if [ "$(cat $alive_domains | wc -l)" -ge "1" ]; then
		[[ ! -d $output_folder ]] && mkdir $output_folder
		[[ ! -d $FAVOUT ]] && mkdir $FAVOUT
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;198m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  🎨  ANÁLISE FAVICON - Hash Fingerprinting   ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			cat $alive_domains | python3 $SCRIPTPATH/tools/FavFreak/favfreak.py --shodan -o $FAVOUT
		else
			echo -e "\n\033[38;5;81m[+] Análise Favicon 🔎\033[m"
			cat $alive_domains | python3 $SCRIPTPATH/tools/FavFreak/favfreak.py --shodan -o $FAVOUT > $SCRIPTPATH/tmpfavfreak
			rm $SCRIPTPATH/tmpfavfreak
		fi
		echo -e "\033[38;5;81m>>>\033[38;5;141m Todos os hashes salvos em \033[38;5;198m$output_folder/favfreak/*.txt\033[m"
		ORG="$(echo $domain | cut -d '.' -f1)"
		if [ "$SHODANAPIKEY" != "False" ]; then
			echo -e "\033[38;5;81m>>>\033[38;5;141m Procurando ativos de $domain no Shodan\033[m"
			shodan init $SHODANAPIKEY 2>/dev/null
			for hash in $(ls $FAVOUT | cut -d '.' -f1); do
				shodan search org:"$ORG" http.favicon.hash:$hash --fields ip_str,port --separator " " | awk '{print $1":"$2}' | tee -a $output_folder/shodan-results.txt
			done
		fi
		echo -e "\033[38;5;228m[!] Se você não tem a API Key premium do Shodan, pode fazer manualmente!\033[m"
		echo -e "\033[38;5;148m[+] Dorks do Shodan serão salvos em \033[38;5;198m$output_folder/shodan-manual.txt\033[m"
		for a in $(ls $FAVOUT); do
			hash=$(echo "$a" | tr -d "$SCRIPTPATH" | tr -d '/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' | tr -d '\' 2>/dev/null | cut -d '.' -f1 | sed -e 's/,//g')
			if [ "$QUIET" != "True" ]; then
				echo "org:"$ORG" http.favicon.hash:$hash" | tee -a $output_folder/shodan-manual.txt
			else
				echo "org:"$ORG" http.favicon.hash:$hash" >> $output_folder/shodan-manual.txt
			fi
		done
		if [ -e $output_folder/shodan-results.txt ]; then
			if [ "$(cat $output_folder/shodan-results.txt) | wc -l" == "0" ]; then
				rm $output_folder/shodan-results.txt
			fi
		fi
	fi
}


dirFuzz() {
	alive_domains_fuzz="$1"
	output_folder_fuzz="$2"
	if [ "$(cat $alive_domains_fuzz | wc -l)" -ge "1" ];then
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;198m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  📁  FUZZING DE DIRETÓRIOS - Brute Force     ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
		else
			echo -e "\n\033[38;5;81m[+] Fuzzing de Diretórios 🔎\033[m"
		fi
		[[ ! -d $output_folder_fuzz ]] && mkdir $output_folder_fuzz 2>/dev/null
		for d in $(cat $alive_domains_fuzz); do
			dnohttps="$(echo $d| cut -d "/" -f3-)"
			echo -e "\n\033[38;5;148m>>> Fuzzing $d\033[m"
			ffuf -u $d/FUZZ -w $wordlist -t 100 -sf -s | tee $output_folder_fuzz/$dnohttps
		done
	fi
}


googleHacking() {
	output_folder_googledorks="$1"
	if [ -n $output_folder_googledorks ]; then
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;198m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  🔍  GOOGLE DORKS - Gerando Consultas        ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
		else
			echo -e "\n\033[1;36m[+] Dorks Google 🔎\033[m"
		fi
		echo -e "\033[33m>> Todos os resultados serão salvos in $output_folder_googledorks/dorks.txt\033[m"
		[[ ! -d $OUTFOLDER/dorks ]] && mkdir $OUTFOLDER/dorks
		[[ ! -d $output_folder_googledorks ]] && mkdir $output_folder_googledorks 2>/dev/null
		echo "site:$domain intitle:'Web user login'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intitle:'login' 'Are you a patient' 'eRAD'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain inurl:wp-content/uploads/ intitle:'logs'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain inurl:'/lib/editor/atto/plugins/managefiles/' | inurl:'calendar/view.php?view=month'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intext:'password'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:sql ('values * MD5' | 'values * password' | 'values * encrypt')" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain inurl:Dashboard.jspa intext:'Atlassian Jira Project Management Software'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain 'SQL Server Driver][SQL Server]Line 1: Incorrect syntax near'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain 'Warning: mysql_connect(): Access denied for user: 'on line'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:sql 'insert into' (pass|passwd|password)" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain 'Warning: mysql_query()' 'invalid query'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intitle:'Apache2 Ubuntu Default Page: It works'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain 'Your password is * Remember this for later use'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intitle:index.of id_rsa -id_rsa.pub" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allinurl:*.php?txtCodiInfo=" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allinurl:auth_user_file.txt" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:sql +'IDENTIFIED BY' -cvs" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allinurl:'exchange/logon.asp'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allinurl:/examples/jsp/snp/snoop.jsp" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intext:'admin credentials'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allintitle:*.php?filename=*" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain inurl:8080/login" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain 'Index of' inurl:phpmyadmin" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intitle:'index of' inurl:ftp" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allintext:username filetype:log" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain 'index of' 'database.sql.zip'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:sql" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intext:Index of /" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intext:'database dump'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:log username putty" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:xls inurl:'email.xls'" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain intitle:'Index of' wp-admin" | tr "'" '"' >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allintitle:*.php?logon=*" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allintitle:*.php?page=*" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allintitle:admin.php" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allinurl: admin mdb" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain allinurl:'.r{}_vti_cnf/'"  | tr "'" '"'>> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:sql password" >> $output_folder_googledorks/dorks.txt
		echo "site:$domain filetype:STM STM" >> $output_folder_googledorks/dorks.txt
	fi
}


ghDork() {
	out_ghdork="$1"
	if [ "$QUIET" != "True" ]; then
		printf "\n\033[1;32m"
		printf "\t╔════════════════════════════════════════════════╗\n"
		printf "\t║  💻  GITHUB DORKS - Buscando Secrets          ║\n"
		printf "\t╚════════════════════════════════════════════════╝\n"
		printf "\033[m\n"
	else
		echo -e "\n\033[1;36m[+] Dorks GitHub 🔎\033[m"
	fi
	echo -e "\033[33m>> Todos os resultados serão salvos in $out_ghdork/*\033[m"
	[[ ! -d $OUTFOLDER/dorks ]] && mkdir $OUTFOLDER/dorks
	[[ ! -d $out_ghdork ]] && mkdir $out_ghdork 2>/dev/null
	for a in $(cat $DOMAINS); do
		outdir="$out_ghdork/$a.txt"
		if [ "$(cat $DOMAINS | wc -l)" -ge "1" ]; then
			without_suffix=$(echo $a | cut -d . -f1)
			echo -e "$a" >> $outdir
			echo "************ Github Dork Links (must be logged in) *******************" >> $outdir
			echo "  password" >> $outdir
			echo "https://github.com/search?q=%22$a%22+password&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+password&type=Code" >> $outdir
			echo " npmrc _auth" >> $outdir
			echo "https://github.com/search?q=%22$a%22+npmrc%20_auth&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+npmrc%20_auth&type=Code" >> $outdir
			echo " dockercfg" >> $outdir
			echo "https://github.com/search?q=%22$a%22+dockercfg&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+dockercfg&type=Code" >> $outdir
			echo "  pem private" >> $outdir
			echo "https://github.com/search?q=%22$a%22+pem%20private&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+extension:pem%20private&type=Code" >> $outdir
			echo "  id_rsa" >> $outdir
			echo "https://github.com/search?q=%22$a%22+id_rsa&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+id_rsa&type=Code" >> $outdir
			echo " aws_access_key_id" >> $outdir
			echo "https://github.com/search?q=%22$a%22+aws_access_key_id&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+aws_access_key_id&type=Code" >> $outdir
			echo "  s3cfg" >> $outdir
			echo "https://github.com/search?q=%22$a%22+s3cfg&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+s3cfg&type=Code" >> $outdir
			echo " htpasswd" >> $outdir
			echo "https://github.com/search?q=%22$a%22+htpasswd&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+htpasswd&type=Code" >> $outdir
			echo " git-credentials" >> $outdir
			echo "https://github.com/search?q=%22$a%22+git-credentials&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+git-credentials&type=Code" >> $outdir
			echo " bashrc password" >> $outdir
			echo "https://github.com/search?q=%22$a%22+bashrc%20password&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+bashrc%20password&type=Code" >> $outdir
			echo " sshd_config" >> $outdir
			echo "https://github.com/search?q=%22$a%22+sshd_config&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+sshd_config&type=Code" >> $outdir
			echo " xoxp OR xoxb OR xoxa" >> $outdir
			echo "https://github.com/search?q=%22$a%22+xoxp%20OR%20xoxb%20OR%20xoxa&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+xoxp%20OR%20xoxb&type=Code" >> $outdir
			echo "  SECRET_KEY" >> $outdir
			echo "https://github.com/search?q=%22$a%22+SECRET_KEY&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+SECRET_KEY&type=Code" >> $outdir
			echo " client_secret" >> $outdir
			echo "https://github.com/search?q=%22$a%22+client_secret&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+client_secret&type=Code" >> $outdir
			echo " sshd_config" >> $outdir
			echo "https://github.com/search?q=%22$a%22+sshd_config&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+sshd_config&type=Code" >> $outdir
			echo " github_token" >> $outdir
			echo "https://github.com/search?q=%22$a%22+github_token&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+github_token&type=Code" >> $outdir
			echo "  api_key" >> $outdir
			echo "https://github.com/search?q=%22$a%22+api_key&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+api_key&type=Code" >> $outdir
			echo " FTP" >> $outdir
			echo "https://github.com/search?q=%22$a%22+FTP&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+FTP&type=Code" >> $outdir
			echo " app_secret" >> $outdir
			echo "https://github.com/search?q=%22$a%22+app_secret&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+app_secret&type=Code" >> $outdir
			echo "  passwd" >> $outdir
			echo "https://github.com/search?q=%22$a%22+passwd&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+passwd&type=Code" >> $outdir
			echo " s3.yml" >> $outdir
			echo "https://github.com/search?q=%22$a%22+.env&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+.env&type=Code" >> $outdir
			echo " .exs" >> $outdir
			echo "https://github.com/search?q=%22$a%22+.exs&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+.exs&type=Code" >> $outdir
			echo " beanstalkd.yml" >> $outdir
			echo "https://github.com/search?q=%22$a%22+beanstalkd.yml&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+beanstalkd.yml&type=Code" >> $outdir
			echo " deploy.rake" >> $outdir
			echo "https://github.com/search?q=%22$a%22+deploy.rake&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+deploy.rake&type=Code" >> $outdir
			echo " mysql" >> $outdir
			echo "https://github.com/search?q=%22$a%22+mysql&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+mysql&type=Code" >> $outdir
			echo " credentials" >> $outdir
			echo "https://github.com/search?q=%22$a%22+credentials&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+credentials&type=Code" >> $outdir
			echo "  PWD" >> $outdir
			echo "https://github.com/search?q=%22$a%22+PWD&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+PWD&type=Code" >> $outdir
			echo " deploy.rake" >> $outdir
			echo "https://github.com/search?q=%22$a%22+deploy.rake&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+deploy.rake&type=Code" >> $outdir
			echo " .bash_history" >> $outdir
			echo "https://github.com/search?q=%22$a%22+.bash_history&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+.bash_history&type=Code" >> $outdir
			echo " .sls" >> $outdir
			echo "https://github.com/search?q=%22$a%22+.sls&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+PWD&type=Code" >> $outdir
			echo " secrets" >> $outdir
			echo "https://github.com/search?q=%22$a%22+secrets&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+secrets&type=Code" >> $outdir
			echo " composer.json" >> $outdir
			echo "https://github.com/search?q=%22$a%22+composer.json&type=Code" >> $outdir
			echo "https://github.com/search?q=%22$without_suffix%22+composer.json&type=Code" >> $outdir
		fi
	done
	echo -e "\033[32m[+] Output saved in \033[31m$out_ghdork/*.txt\033[m"
	echo -e "\033[1;31m[!] Check the Dorks manually!\033[m"
}


credStuff() {
	len="$1"
	output_folder="$2"
	[[ ! -d $output_folder ]] && mkdir $output_folder
	[[ ! -d $output_folder/credstuff ]] && mkdir $output_folder/credstuff
	if [ "$domain" != "" ]; then
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[1;32m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  🔐  CREDENTIAL STUFFING - Hunting Leaks     ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			$SCRIPTPATH/tools/CredStuff-Auxiliary/CredStuff_Auxiliary/main.sh $domain $1 | tee -a $output_folder/credstuff/credstuff.txt
		else
			echo -e "\n\033[1;36m[+] Cred Stuff 🔎\033[m"
			$SCRIPTPATH/tools/CredStuff-Auxiliary/CredStuff_Auxiliary/main.sh $domain $1 >> $output_folder/credstuff/credstuff.txt
		fi
	fi
}


screenshots() {
	alive_domains_screenshots="$1"
	out_screenshots="$2"
	if [ -r $alive_domains_screenshots ]; then
		if [ "$(cat $alive_domains_screenshots | wc -l)" -ge "1" ]; then
			if [ "$QUIET" != "True" ]; then
				printf "\n\033[1;32m"
				printf "\t╔════════════════════════════════════════════════╗\n"
				printf "\t║  📸  SCREENSHOTS - Capturando Páginas         ║\n"
				printf "\t╚════════════════════════════════════════════════╝\n"
				printf "\033[m\n"
			else
				echo -e "\n\033[1;36m[+] Screenshots 🔎\033[m"
			fi
			# Executar EyeWitness com tratamento de erros (timeouts de Chrome são esperados)
			python3 $SCRIPTPATH/tools/EyeWitness/Python/EyeWitness.py --web --no-prompt -f $alive_domains_screenshots -d $out_screenshots --selenium-log-path $out_screenshots/selenium-log.txt --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" 2>&1 | grep -v "Chrome WebDriver initialization error" | grep -v "Timed out receiving message from renderer" | grep -v "Stacktrace:" | grep -v "^#[0-9]" || true
			echo -e "\033[38;5;148m[+] Screenshots concluídos (erros de timeout são normais e não afetam resultados)\033[m"
		fi
	fi
}


portscan() {
	portscan_domains="$1"
	ips="$2"
	output_folder="$3"
	if [ "$(cat $portscan_domains | wc -l)" -ge "1" ] && [ "$(cat $ips | wc -l)" -ge "1" ]; then
		[[ ! -d $Ooutput_folder ]] && mkdir $output_folder 2>/dev/null
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[1;32m"
			printf "\t╔════════════════════════════════════════════════╗\n"
			printf "\t║  🔌  PORT SCAN - Mapeando Serviços            ║\n"
			printf "\t╚════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
			echo -e "\n\033[36m>>>\033[35m Executando Nmap 🔍\033[m\n"
			nmap -iL $portscan_domains --top-ports 5000 --max-rate=50000 -oG $output_folder/nmap.txt
			echo -e "\n\033[36m>>>\033[35m Executando Masscan 🔍\033[m\n"
			sudo masscan -p1-65535 -iL $ips --max-rate=50000 -oG $output_folder/masscan.txt
			echo -e "\n\033[36m>>>\033[35m Executando Naabu 🔍\033[m\n"
			cat $portscan_domains | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe | tee -a $output_folder/naabu.txt
		else
			echo -e "\n\033[1;36m[+] Scan de Portas 🔎\033[m"
			echo -e -n "\n\033[36m>>>\033[35m Executando Nmap 🔍\033[m\n"
			nmap -iL $portscan_domains --top-ports 5000 --max-rate=50000 -oG $output_folder/nmap.txt 2>/dev/null > $SCRIPTPATH/nmaptemp
			rm $SCRIPTPATH/nmaptemp
			echo "✅"
			echo -e "\n\033[36m>>>\033[35m Executando Masscan 🔍\033[m\n"
			sudo masscan -p1-65535 -iL $ips --max-rate=50000 -oG $output_folder/masscan.txt > $SCRIPTPATH/masscantemp
			rm $SCRIPTPATH/masscantemp
			echo -e -n "\n\033[36m>>>\033[35m Executando Naabu 🔍\033[m\n"
			cat $portscan_domains | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe >> $output_folder/naabu.txt
			echo "✅"
		fi
	fi
}


linkDiscovery() {
    alive_domains="$1"
    output_folder="$2"

    # Verifica se o arquivo tem conteúdo
    if [ "$(cat "$alive_domains" | wc -l)" -ge "1" ]; then
        if [ "$QUIET" != "True" ]; then
            printf "\n\033[38;5;228m"
            printf "\t╔═════════════════════════════════════════════════╗\n"
            printf "\t║  🔗  DESCOBERTA DE LINKS - Crawling URLs  🔗   ║\n"
            printf "\t╚═════════════════════════════════════════════════╝\n"
            printf "\033[m\n"
        else
            echo -e -n "\n\033[1;36m[+] Descoberta de Links 🔎\033[m"
        fi

        [[ ! -d "$output_folder" ]] && mkdir "$output_folder"
        [[ ! -d "$output_folder/hakrawler" ]] && mkdir "$output_folder/hakrawler" 2>/dev/null
        [[ ! -d "$output_folder/waybackurls" ]] && mkdir "$output_folder/waybackurls" 2>/dev/null

        for d in $(cat "$alive_domains"); do
            dnohttps="$(echo $d | cut -d "/" -f3-)"
            echo "$d" | hakrawler -subs >> "$output_folder/hakrawler/$dnohttps.txt"

            # Tentar waybackurls primeiro, se falhar usar curl direto na API
            echo "$d" | waybackurls >> "$output_folder/waybackurls/$dnohttps.txt" 2>/dev/null

            # Fallback: usar curl direto na API do Wayback Machine
            if [ ! -s "$output_folder/waybackurls/$dnohttps.txt" ]; then
                timestamp=$(date +%s%3N)
                curl -s "https://web.archive.org/web/timemap/json?url=$dnohttps&matchType=prefix&collapse=urlkey&output=json&fl=original&filter=\!statuscode%3A%5B45%5D..&limit=10000&_=$timestamp" \
                | jq -r '.[1:][]|.[0]' 2>/dev/null | sort -u >> "$output_folder/waybackurls/$dnohttps.txt"
            fi
        done

        cat "$output_folder/hakrawler/"*.txt | cut -d "]" -f2- | sed -e 's/^[ \t]*//' >> "$output_folder/all.txt"
        cat "$output_folder/waybackurls/"*.txt | sed -e 's/^[ \t]*//' >> "$output_folder/all.txt"
        
        sort -u "$output_folder/all.txt" -o "$output_folder/all.txt"

        if [ "$QUIET" == "True" ]; then
            echo " ✅"
        fi

        all="$(cat "$output_folder/all.txt" | wc -l)"
        echo -e "\033[35m[+] Encontrados \033[31m$all\033[35m links\033[m"
    fi
}


endpointsEnumeration() {
	alive_domains="$1"
	output_folder="$2"
	echo "Dominios:\n$1"
	if [ "$(cat $alive_domains | wc -l)" -ge "1" ]; then
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;141m"
			printf "\t╔═══════════════════════════════════════════════════╗\n"
			printf "\t║  📡  ENUMERAÇÃO DE ENDPOINTS - Caça a Parâmetros ║\n"
			printf "\t╚═══════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
		else
			echo -e "\n\033[1;36m[+] Enumeração de Endpoints 🔎\033[m"
		fi
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[36m>>>\033[35m Extracting URLs 🔍\033[m"
			xargs -a $alive_domains -I@ bash -c "$SCRIPTPATH/.venv/bin/paramspider -d @ -s 2>/dev/null" >> $output_folder/all.txt
		else
			echo -e -n "\n\033[36m>>>\033[35m Extracting URLs 🔍\033[m"
			xargs -a $alive_domains -I@ bash -c "$SCRIPTPATH/.venv/bin/paramspider -d @ -s 2>/dev/null" >> $output_folder/all.txt
			echo " ✅"
		fi
		sort -u $output_folder/all.txt -o $output_folder/all.txt
		[[ ! -d $output_folder/js ]] && mkdir $output_folder/js
		echo -e "\n\033[36m>>>\033[35m Enumerating Javascript files 🔍\033[m"
		xargs -P 500 -a $DOMAINS -I@ bash -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 bash -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew' | grep -Eo "(http|https)://[^/\"].*\.js+" >> $output_folder/js/js.txt
		cat $alive_domains | waybackurls | grep -iE '\.js' | grep -iEv '(\.jsp|\.json)' >> $output_folder/js/js.txt
		sort -u $output_folder/js/js.txt -o $output_folder/js/js.txt
		jslen="$(cat $output_folder/js/js.txt | wc -l)"
		echo -e "\033[32m[+] Encontrados \033[31m$jslen\033[32m JS files\033[m"
		cat $output_folder/js/js.txt | anti-burl | awk '{print $4}' | sort -u >> $output_folder/js/AliveJS.txt
		sort -u $output_folder/js/AliveJS.txt -o $output_folder/js/AliveJS.txt
		jsalivelen="$(cat $output_folder/js/AliveJS.txt | wc -l)"
		echo -e "\033[32m[+] Encontrados \033[31m$jsalivelen\033[32m alive JS files\033[m"
	fi
}


findVuln() {
	alive_domains="$1"
	output_folder="$2"
	if [ "$(cat $alive_domains | wc -l)" -ge "1" ]; then
		if [ "$QUIET" != "True" ]; then
			printf "\n\033[38;5;198m"
			printf "\t╔══════════════════════════════════════════════════╗\n"
			printf "\t║  🔥  SCAN DE VULNERABILIDADES - Hunting Bugs 🔥 ║\n"
			printf "\t╚══════════════════════════════════════════════════╝\n"
			printf "\033[m\n"
		else
			echo -e "\n\033[1;36m[+] Vulnerabilidades 🔎\033[m"
		fi
		echo -e "\n\033[36m[+] Finding vulnerabilities with Nuclei 🔍\033[m"
		[[ ! -d $HOME/nuclei-templates ]] && nuclei --update-templates
		[[ ! -d $output_folder ]] && mkdir $output_folder 2>/dev/null
		nuclei -l $alive_domains -t $HOME/nuclei-templates/ -o $output_folder/nuclei.txt --silent
		echo -e "\n\033[36m>>>\033[35m Finding XSS 🤖\033[m"
		list="$OUTFOLDER/link-discovery/all.txt"
		[[ ! -d $output_folder/xss-discovery ]] && mkdir $output_folder/xss-discovery 2>/dev/null
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[36m>>>\033[34m Finding XSS with Gxss🤖\033[m"
			cat $OUTFOLDER/link-discovery/all.txt | anti-burl | awk '{print $4}' | Gxss -p XSS | sed '/^$/d' | tee -a $output_folder/xss-discovery/temppossíveis-xss.txt
		else
			echo -e -n "\n\033[36m>>>\033[34m Finding XSS with Gxss🤖\033[m"
			cat $OUTFOLDER/link-discovery/all.txt | anti-burl | awk '{print $4}' | Gxss -p XSS >> $output_folder/xss-discovery/temppossíveis-xss.txt
			echo " ✅"
		fi
		sed '/^$/d' $output_folder/xss-discovery/temppossíveis-xss.txt > $output_folder/xss-discovery/possíveis-xss.txt
		sort -u $output_folder/xss-discovery/possíveis-xss.txt -o $output_folder/xss-discovery/possíveis-xss.txt
		echo -e "\n\033[36m>>>\033[34m Finding XSS with Oneliner🤖\033[m"
		cat $output_folder/xss-discovery/possíveis-xss.txt | grep "=" | qsreplace '"><script>alert(1)</script>' | while read -r url; do
		req="$(curl --silent --path-as-is --insecure $url | grep -qs '<script>alert(1)')"
		if [ "$req" != "" ]; then
			if [ "$QUIET" != "True" ]; then
				echo "\033[1;31m$req\033[m"
				echo "$req" | tee -a $output_folder/xss-discovery/xss.txt
			else
				echo "$req" >> $output_folder/xss-discovery/xss.txt
			fi
			echo -e "\033[1;32m[+] $url\033[1;31m VULNERABLE\033[m"	
		fi
	done
	rm $output_folder/xss-discovery/temppossíveis-xss.txt 
	if [ "$FUZZ" == "True" ]; then
		for a in $(cat $output_folder/xss-discovery/possíveis-xss.txt); do
			echo -e "\033[32m[+] Fuzzing $a\033[m"
			python3 $SCRIPTPATH/tools/XSStrike/xsstrike.py -u $a
		done
		echo -e "\n\033[36m>>>\033[34m Finding XSS with Dalfox🤖\033[m"
		gospider -S $OUTFOLDER/subdomains/alive.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe --skip-bav --silence | tee -a $output_folder/xss-discovery/xss.txt
	fi
	xssfound="$(cat $output_folder/xss-discovery/*.txt | wc -l)"
	echo -e "\033[1;33m[!] Encontrados \033[1;31m$xssfound\033[33m possíveiss XSS\033[m"
	echo -e "\n\033[36m>>>\033[35m Finding 403 HTTP Responses 🤖\033[m"
	for a in $(cat $DOMAINS); do
		r="$(curl -I -s -k $a | grep 'HTTP' | awk '{print $2}')"
		if [ "$r" == "403" ]; then
			echo -e "\033[32m$a \033[35m[$r]\033[m"
			echo $a >> $output_folder/403.txt
			if [ "$FUZZ" == "True" ]; then
				$SCRIPTPATH/scripts/bypass-403.sh $a
			fi
		fi
	done
	if [ -e $output_folder/403.txt ]; then
		xxxfound="$(cat $output_folder/403.txt | wc -l)"
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$xxxfound\033[33m 403 Status Code\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m 403 Status Code\033[m"
	fi

	echo -e "\n\033[36m>>>\033[35m Finding possíveis Open Redirect 🤖\033[m"
	grepVuln "$open_redir_parameters" "$list" "$output_folder/possíveis-open-redir.txt"
	if [ -e $output_folder/open-redir.txt ]; then
		lenopenredir="$(cat $output_folder/open-redir.txt | wc -l)"
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$lenopenredir\033[33m possíveiss Open Redirects\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveiss Open Redirects\033[m"
	fi

	echo -e "\n\033[36m>>>\033[35m Finding possíveis RCE 🤖\033[m"
	grepVuln "$rce_parameters" "$list" "$output_folder/rce.txt"
	if [ -e $output_folder/rce.txt ]; then
		lenrce="$(cat $output_folder/rce.txt | wc -l)"
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$lenrce\033[33m possíveiss RCEs\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveiss RCEs\033[m"
	fi

	echo -e "\n\033[36m>>>\033[35m Finding possíveis LFI 🤖\033[m"
	grepVuln "$lfi_parameters" "$list" "$output_folder/lfi.txt"
	cat $list | gf lfi >> $output_folder/lfi.txt
	if [ -e $output_folder/lfi.txt ]; then
		sort -u $output_folder/lfi.txt -o $output_folder/lfi.txt
		lenlfi="$(cat $output_folder/lfi.txt | wc -l)"
		if [ "$FUZZ" == "True" ]; then
			if [ "$(cat $output_folder/lfi.txt | wc -l)" -ge "1" ]; then
				cat $output_folder/lfi.txt | qsreplace FUZZ | while read url; do
				echo -e "\n\033[1;32m>>> Fuzzing $url\033[m"
				ffuf -u $url -mr "root:x" -w $SCRIPTPATH/wordlists/lfi.txt -sf -s -t 100
			done
			fi
		fi
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$lenlfi\033[33m possíveiss LFIs\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveiss LFIs\033[m"
	fi
	echo -e "\n\033[36m>>>\033[35m Finding possíveis SQLi 🤖\033[m"
	cat $DOMAINS | waybackurls | gf sqli >> $output_folder/possíveis-sqli.txt
	if [ -e "$output_folder/possíveis-sqli.txt" ]; then
		sqlifound="$(cat $output_folder/possíveis-sqli.txt | wc -l)"
		if [ "$sqlifound" -ge "1" ]; then
			echo -e "\033[1;33m[!] Encontrados \033[1;31m$sqlifound\033[33m possíveiss SQLi\033[m"
		else
			echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveiss SQLi\033[m"
		fi
	fi
	if [ "$FUZZ" == "True" ]; then
		sqlmap -m $output_folder/possíveis-sqli.txt --batch --random-agent --level 1 | tee -a $output_folder/sqli.txt
	fi
	fi
}


if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	show_help
	exit
fi

while getopts ":d:w:t:g:s:q:o:f:" ops; do
	case "${ops}" in
		d)
			domain=${OPTARG}
			;;
		w)
			wordlist=${OPTARG}
			;;
		g)
			GHAPIKEY=${OPTARG}
			;;
		s)
			SHODANAPIKEY=${OPTARG}
			;;
		q)
			QUIET="True"
			;;
		o)
			OUTFOLDER=${OPTARG}
			;;
		:)
			if [ "${OPTARG}" == "q" ]; then
				QUIET="True"
			elif [ "${OPTARG}" == "f" ]; then
				FUZZ="True"
			else
				echo -e "\033[1;31m[-] Error: -${OPTARG} requires an argument!\033[m"
				exit
			fi
			;;
		\?)
			echo -e "\033[1;31m[-] Error: -${OPTARG} is an Invalid Option"
			exit
			;;
	esac
done

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
if [ "$OUTFOLDER" == "" ]; then
	OUTFOLDER="$SCRIPTPATH/$domain"
fi
DOMAINS="$OUTFOLDER/subdomains/subdomains.txt"
dep_falt=0

show_banner

echo -e "\033[38;5;81m[!] Verificando dependências\033[m"
if [ ! -e $SCRIPTPATH/requirements.txt ]; then
	echo -e "\033[38;5;198m[-] Não foi possível verificar dependências :(\033[m"
	exit
else
	for a in $(cat $SCRIPTPATH/requirements.txt); do
		if ! command -v $a >/dev/null ; then
			echo -e "\033[38;5;198m[-] $a\033[m"
			dep_falt="1"
		else
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;148m[+] $a\033[m"
			fi
		fi
	done
fi

if [ ! -e $SCRIPTPATH/tools ]; then
	echo -e "\033[38;5;198m[-] Pasta tools não encontrada, execute o script de instalação\033[m"
	dep_falt="1"
else
	if [ ! -e $SCRIPTPATH/tools/CredStuff-Auxiliary ]; then
		dep_falt="1"
	fi
	if [ ! -e $SCRIPTPATH/tools/EyeWitness ]; then
		dep_falt="1"
	fi
	if [ ! -e $SCRIPTPATH/tools/FavFreak ]; then
		dep_falt="1"
	fi
	if [ ! -e $SCRIPTPATH/tools/github-search ]; then
		dep_falt="1"
	fi
	if [ ! -e $SCRIPTPATH/tools/ParamSpider ]; then
		dep_falt="1"
	fi
	if [ ! -e $SCRIPTPATH/tools/XSStrike ]; then
		dep_falt="1"
	fi
	if [ ! -e $SCRIPTPATH/tools/SubDomainizer.py ]; then
		dep_falt="1"
	fi
fi

if [ "$dep_falt" == "0" ]; then
	echo -e "\033[38;5;148m[+] Tudo certo! ✅\033[m"
else
	echo -e "\033[38;5;198m[-] Faltam dependências! ❌\033[m"
	echo -e "Execute \033[38;5;148m./installation.sh\033[m"
	exit
fi

if [ -z "$domain" ]; then
	echo -e "\n\033[38;5;198m[-] Domínio não especificado! ❌\033[m"
	exit
fi
if [ -z "$wordlist" ]; then
	echo -e "\n\033[38;5;148m<<  \033[mVocê não escolheu uma wordlist. Aqui estão suas opções: \033[38;5;148m >>\033[m"
	for a in $(ls $SCRIPTPATH/wordlists/); do
		pwdWL="$(cd $SCRIPTPATH/wordlists/; pwd)"
		echo -e "\033[38;5;148m[+] $pwdWL/$a\033[m"
	done
	exit
fi
if [ -z "$GHAPIKEY" ]; then
	GHAPIKEY="False"
fi

if [ -z "$SHODANAPIKEY" ]; then
	SHODANAPIKEY="False"
fi

[[ ! -d $OUTFOLDER ]] && mkdir $OUTFOLDER 2>/dev/null

# Inicializa sistema de checkpoints
init_checkpoint
show_banner
show_progress

# ╔═══════════════════════════════════════════════════════════════════════╗
# ║                         PIPELINE DE RECONHECIMENTO                    ║
# ╚═══════════════════════════════════════════════════════════════════════╝

run_step "asn_enum" asnEnum $domain $OUTFOLDER/asn

run_step "subdomain_enum" subdomainEnumeration $domain $OUTFOLDER/subdomains

run_step "organize_domains" organizeDomains $DOMAINS $OUTFOLDER/subdomains

run_step "subdomain_takeover" subdomainTakeover $DOMAINS $OUTFOLDER/subdomains/subdomain-takeover

run_step "dns_lookup" dnsLookup $DOMAINS $OUTFOLDER

run_step "check_active" checkActive $DOMAINS $OUTFOLDER/subdomains

run_step "waf_detect" wafDetect $OUTFOLDER/subdomains/alive.txt

run_step "favicon_analysis" favAnalysis $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/favicon-analysis

#run_step "directory_fuzzing" dirFuzz $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/fuzz

run_step "cred_stuff" credStuff 500 $OUTFOLDER/dorks

run_step "google_hacking" googleHacking $OUTFOLDER/dorks/google-dorks

run_step "github_dorks" ghDork $OUTFOLDER/dorks/github-dorks

run_step "screenshots" screenshots $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/$domain-screenshots

#run_step "port_scanning" portscan $DOMAINS $OUTFOLDER/DNS/ip_only.txt $OUTFOLDER/portscan/

run_step "link_discovery" linkDiscovery $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/link-discovery

run_step "endpoints_enum" endpointsEnumeration $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/link-discovery

run_step "vulnerability_scan" findVuln $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/vuln

org="$(echo $domain | cut -d '.' -f1)"
if [ -e $OUTFOLDER/asn/$org.txt ]; then
	asn="$(cat $OUTFOLDER/asn/$org.txt | wc -l)"
else
	asn="0"
fi
subsfound="$(cat $DOMAINS | wc -l)"
subsalive="$(cat $OUTFOLDER/subdomains/alive.txt | wc -l)"
if [ -e $OUTFOLDER/subdomains.txt/takeover.txt ]; then
	takeofound="$(cat $OUTFOLDER/subdomains.txt/takeover.txt | wc -l)"
fi
ips="$(cat $OUTFOLDER/DNS/ip_only.txt | wc -l)"
favfound="$(cat $OUTFOLDER/favicon-analysis/favfreak/*.txt | wc -l)"
fuzzdir="$(ls $OUTFOLDER/fuzz | wc -l)"
fuzzdirfound="$(cat $OUTFOLDER/fuzz/* | wc -l)"
jsfound="$(cat $OUTFOLDER/link-discovery/js/js.txt | wc -l)"
jsalive="$(cat $OUTFOLDER/link-discovery/js/AliveJS.txt | wc -l)"
lfound="$(cat $OUTFOLDER/link-discovery/all.txt | wc -l)"
foundvuln="$(($(cat $OUTFOLDER/vuln/* 2>/dev/null | wc -l)+$(cat $OUTFOLDER/vuln/xss-discovery/* | wc -l)))"
echo -e "\033[38;5;198m====================================================================================================================\033[m"
echo -e "\033[38;5;198m====================\033[38;5;148m Resultados Finais \033[38;5;198m====================\033[m"
echo -e "\033[38;5;148m[+] ASNs Encontrados: \033[38;5;198m$asn\033[m"
echo -e "\033[38;5;148m[+] Subdomínios Encontrados: \033[38;5;198m$subsfound\033[m"
echo -e "\033[38;5;148m[+] Subdomínios Ativos Encontrados: \033[38;5;198m$subsalive\033[m"
if [ -e $OUTFOLDER/subdomains.txt/takeover.txt ] && [ "$(cat $OUTFOLDER/subdomains.txt/takeover.txt | wc -l)" -ge "1" ]; then
	echo -e "\033[38;5;148m[+] Subdomain Takeover Encontrados: \033[38;5;198m$takeofound\033[m"
else
	echo -e "\033[38;5;148m[+] Subdomain Takeover Encontrados: \033[38;5;198m0\033[m"
fi
echo -e "\033[38;5;148m[+] IPs Encontrados: \033[38;5;198m$ips\033[m"
if [ -e "$OUTFOLDER/DNS/dnsrecon.txt" ]; then
	echo -e "\033[38;5;148m[+] Enumeração DNS: ✅\033[m"
fi
echo -e "\033[38;5;148m[+] Hashes de Favicons Encontrados: \033[38;5;198m$favfound\033[m"
echo -e "\033[38;5;148m[+] Brute Force em diretórios feito em \033[38;5;198m$fuzzdir\033[38;5;148m domínios com \033[38;5;198m$fuzzdirfound\033[38;5;148m diretórios encontrados\033[m"
echo -e "\033[38;5;148m[+] Mais de \033[38;5;198m$lfound\033[38;5;148m links foram encontrados\033[m"
echo -e "\033[38;5;148m[+] \033[38;5;198m$jsfound\033[38;5;148m Arquivos JS Encontrados, entre eles \033[38;5;198m$jsalive\033[38;5;148m estão ativos\033[m"
echo -e "\033[38;5;148m[+] Mais de \033[38;5;198m$foundvuln\033[38;5;148m possíveis VULNERABILIDADES encontradas\033[m"
echo -e "\033[38;5;148m[+] Verifique \033[38;5;198m$OUTFOLDER\033[38;5;148m e analise todos os dorks manualmente, pesquisas no Shodan, Port Scans e muito mais!\033[m"
echo -e "\033[38;5;148mBoa caçada! 🎯\033[m"
echo -e "\033[38;5;198m====================\033[38;5;148m CONCLUÍDO \033[38;5;198m====================\033[m"
echo -e "\033[38;5;198m====================================================================================================================\033[m"
