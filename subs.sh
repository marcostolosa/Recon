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
	echo -e "\n\tUso: \033[38;5;208m./subs.sh \033[38;5;198m[ -d dominio ]\033[38;5;81m [ -w wordlist.txt ]\033[38;5;228m [ -g GitHub-API_KEY ] [ -s Shodan-API_KEY ]\033[m [ -q ] [ -f ] [ -D ] [ -P ]"
	echo -e "\n\t-d  | (obrigatório) : Seu \033[38;5;198malvo\033[m"
	echo -e "\t-w  | (obrigatório) : Caminho para sua \033[38;5;81mwordlist\033[m"
	echo -e "\t-q  | (opcional)    : Modo silencioso"
	echo -e "\t-o  | (opcional)    : Pasta de saída. Padrão é a pasta do script"
	echo -e "\t-f  | (opcional)    : Ativar modo Fuzzing de vulnerabilidades"
	echo -e "\t-D  | (opcional)    : Ativar Directory Fuzzing (brute force de diretórios)"
	echo -e "\t-P  | (opcional)    : Ativar Port Scanning (requer sudo)"
	echo -e "\t-Q  | (opcional)    : Quick Mode - pula discovery (ASN/subdomain/links), apenas testing"
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

# Etapas que SEMPRE devem executar (discovery de novos alvos)
ALWAYS_RUN_STEPS=(
	"asn_enum"
	"subdomain_enum"
	"organize_domains"
	"check_active"
	"link_discovery"
	"endpoints_enum"
)

# Variável global para rastrear se novos alvos foram encontrados
NEW_TARGETS_FOUND=0

# Variável global para quick mode
QUICK_MODE="False"

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

# NOVO: Detecta se re-scan recente foi executado e sugere quick mode
check_recent_scan() {
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	local scan_history="$OUTFOLDER/.scan_history"

	if [ ! -f "$checkpoint_file" ]; then
		return
	fi

	# Pega timestamp do último scan completo
	local last_scan=$(grep "^# Scan iniciado em:" "$checkpoint_file" | tail -1 | cut -d: -f2- | xargs)

	if [ -z "$last_scan" ]; then
		return
	fi

	# Calcula horas desde último scan
	local last_scan_epoch=$(date -d "$last_scan" +%s 2>/dev/null || date -j -f "%Y-%m-%d %H:%M:%S" "$last_scan" +%s 2>/dev/null)
	local now_epoch=$(date +%s)
	local hours_diff=$(( (now_epoch - last_scan_epoch) / 3600 ))

	# Se scan foi <6h atrás e não está em quick mode, sugere
	if [ "$hours_diff" -lt 6 ] && [ "$QUICK_MODE" != "True" ]; then
		echo -e "\033[38;5;228m"
		echo -e "╔════════════════════════════════════════════════════════════════════╗"
		echo -e "   ⚡ OTIMIZAÇÃO SUGERIDA                                             "
		echo -e "╚════════════════════════════════════════════════════════════════════╝"
		echo -e "\033[38;5;228m[!] Último scan foi há $hours_diff horas\033[m"
		echo -e "\033[38;5;148m[TIP] Para re-rodar apenas testing (pular discovery), use:\033[m"
		echo -e "\033[38;5;81m    ./subs.sh -d $domain -w $wordlist -Q\033[m"
		echo -e "\033[38;5;228m[TIP] Quick mode economiza ~95 min re-usando descobertas existentes\033[m"
		echo -e "\033[m"

		# Pausa 5 segundos para usuário ver (pode cancelar)
		echo -e "\033[38;5;228mContinuando full scan em 5 segundos (Ctrl+C para cancelar)...\033[m"
		sleep 5
	fi

	# Registra execução no histórico
	echo "$(date '+%Y-%m-%d %H:%M:%S'),quick_mode:$QUICK_MODE" >> "$scan_history"

	# Analisa últimas 3 execuções para detectar alvo estável
	if [ -f "$scan_history" ] && [ $(cat "$scan_history" | wc -l) -ge 3 ]; then
		local recent_runs=$(tail -3 "$scan_history")
		# TODO: Adicionar análise de NEW_TARGETS_FOUND das últimas 3 runs
		# (requer persistir esse valor no checkpoint - feature futura)
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

# Banner de step limpo e profissional
show_step_banner() {
	local emoji="$1"
	local title="$2"
	local color="${3:-81}" # Cyan por padrão

	echo ""
	echo -e "   \033[38;5;${color}m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[m"
	echo -e "   \033[1;38;5;231m${emoji}  ${title}\033[m"
	echo -e "   \033[38;5;240m────────────────────────────────────────────────────────────\033[m"
	echo ""
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

	echo ""
	echo -e "   \033[38;5;240m[\033[m\033[38;5;81m$completed_steps\033[38;5;240m/\033[m\033[38;5;81m$total_steps\033[38;5;240m]\033[m \033[38;5;148m${percentage}% completo\033[m"
	echo ""
}

# Faz merge inteligente de resultados (adiciona apenas novos)
merge_results() {
	local new_file="$1"
	local target_file="$2"

	if [ ! -f "$new_file" ]; then
		echo "0"  # Retorna 0 novos itens
		return
	fi

	local old_count=0
	local new_count=0
	local added=0

	if [ ! -f "$target_file" ]; then
		# Se arquivo alvo não existe, todos são novos
		mv "$new_file" "$target_file"
		new_count=$(cat "$target_file" 2>/dev/null | wc -l)
		echo "$new_count"
		NEW_TARGETS_FOUND=$((NEW_TARGETS_FOUND + new_count))
	else
		# Conta items existentes
		old_count=$(cat "$target_file" 2>/dev/null | wc -l)

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

		# Conta novos items
		new_count=$(cat "$target_file" 2>/dev/null | wc -l)
		added=$((new_count - old_count))

		echo "$added"
		NEW_TARGETS_FOUND=$((NEW_TARGETS_FOUND + added))
	fi
}

# ╔═══════════════════════════════════════════════════════════════════════╗
# ║                    SISTEMA DE TIMESTAMPING                            ║
# ╚═══════════════════════════════════════════════════════════════════════╝

# Cria snapshot timestamped de arquivo e registra novos itens em CSV tracker
timestamp_and_track() {
	local file="$1"           # Arquivo atual (ex: subdomains.txt)
	local label="$2"          # Label para CSV (ex: "subdomain", "url", "alive_domain")
	local timestamp=$(date '+%Y%m%d_%H%M%S')
	local datestamp=$(date '+%Y-%m-%d %H:%M:%S')

	if [ ! -f "$file" ]; then
		return
	fi

	# Cria diretório de archives se não existir
	local archive_dir="$(dirname "$file")/.history"
	[ ! -d "$archive_dir" ] && mkdir -p "$archive_dir"

	# Cria diretório de trackers se não existir
	local tracker_dir="$OUTFOLDER/.trackers"
	[ ! -d "$tracker_dir" ] && mkdir -p "$tracker_dir"

	local tracker_file="$tracker_dir/${label}_tracker.csv"
	local archive_file="$archive_dir/$(basename "$file").$timestamp"
	local prev_file=$(ls -t "$archive_dir"/$(basename "$file").* 2>/dev/null | head -1)

	# Inicializa CSV se não existir
	if [ ! -f "$tracker_file" ]; then
		echo "item,first_seen,last_seen,status" > "$tracker_file"
	fi

	# Cria snapshot timestamped
	cp "$file" "$archive_file"

	# Identifica novos itens (comparando com snapshot anterior)
	local new_items_count=0
	if [ -n "$prev_file" ] && [ -f "$prev_file" ]; then
		# Items no arquivo atual que não estavam no anterior = NOVOS
		comm -13 <(sort "$prev_file") <(sort "$file") > "$archive_dir/.new_items.tmp"
		new_items_count=$(cat "$archive_dir/.new_items.tmp" | wc -l)

		# Atualiza CSV tracker para cada novo item
		while IFS= read -r item; do
			if [ -n "$item" ]; then
				# Adiciona novo item ao tracker
				echo "\"$item\",\"$datestamp\",\"$datestamp\",\"active\"" >> "$tracker_file"
			fi
		done < "$archive_dir/.new_items.tmp"

		# Atualiza last_seen para itens que já existiam
		comm -12 <(sort "$prev_file") <(sort "$file") > "$archive_dir/.existing_items.tmp"
		while IFS= read -r item; do
			if [ -n "$item" ]; then
				# Escapa caracteres especiais para sed
				escaped_item=$(echo "$item" | sed 's/[[\.*^$()+?{|]/\\&/g')
				# Atualiza last_seen (última coluna)
				sed -i "s|^\"$escaped_item\",\(.*\),\".*\",\(.*\)$|\"$escaped_item\",\1,\"$datestamp\",\2|" "$tracker_file" 2>/dev/null
			fi
		done < "$archive_dir/.existing_items.tmp"

		rm -f "$archive_dir/.new_items.tmp" "$archive_dir/.existing_items.tmp"
	else
		# Primeira execução - todos são novos
		new_items_count=$(cat "$file" | wc -l)
		while IFS= read -r item; do
			if [ -n "$item" ]; then
				echo "\"$item\",\"$datestamp\",\"$datestamp\",\"active\"" >> "$tracker_file"
			fi
		done < "$file"
	fi

	# Limita archives a últimos 30 dias (cleanup automático)
	find "$archive_dir" -name "$(basename "$file").*" -type f -mtime +30 -delete 2>/dev/null

	if [ "$QUIET" != "True" ] && [ "$new_items_count" -gt 0 ]; then
		echo -e "\033[38;5;148m   [TIMESTAMP] $new_items_count novos itens registrados em $tracker_file\033[m"
	fi
}

# Query helper: Lista novos itens descobertos nas últimas N horas
get_new_items() {
	local tracker_file="$1"
	local hours="${2:-24}"  # Default: últimas 24h

	if [ ! -f "$tracker_file" ]; then
		return
	fi

	local cutoff_time=$(date -d "$hours hours ago" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v-${hours}H '+%Y-%m-%d %H:%M:%S' 2>/dev/null)

	# Retorna items onde first_seen > cutoff_time
	awk -F',' -v cutoff="$cutoff_time" 'NR>1 && $2 > cutoff {gsub(/"/, "", $1); print $1}' "$tracker_file"
}

# Query helper: Gera arquivo com apenas novos alvos para testing incremental
generate_new_targets_file() {
	local hours="${1:-24}"
	local output="$OUTFOLDER/.trackers/new_targets_last_${hours}h.txt"

	# Coleta novos alvos de todos os trackers relevantes
	> "$output"  # Limpa arquivo

	for tracker in "$OUTFOLDER/.trackers"/*_tracker.csv; do
		if [ -f "$tracker" ]; then
			get_new_items "$tracker" "$hours" >> "$output"
		fi
	done

	sort -u "$output" -o "$output"

	local count=$(cat "$output" | wc -l)
	if [ "$QUIET" != "True" ] && [ "$count" -gt 0 ]; then
		echo -e "\033[38;5;148m[INCREMENTAL] $count novos alvos nas últimas ${hours}h salvos em:\033[m"
		echo -e "\033[38;5;81m   $output\033[m"
	fi

	echo "$output"
}

# Wrapper para executar etapas com checkpoint
run_step() {
	local step_name="$1"
	local step_function="$2"
	shift 2
	local step_args="$@"

	# Verifica se é uma etapa de discovery (sempre executar)
	local is_always_run=false
	for always_step in "${ALWAYS_RUN_STEPS[@]}"; do
		if [ "$step_name" == "$always_step" ]; then
			is_always_run=true
			break
		fi
	done

	# NOVO: Quick mode - pula etapas de discovery (re-usa resultados existentes)
	if [ "$QUICK_MODE" == "True" ] && [ "$is_always_run" == "true" ]; then
		if check_step "$step_name"; then
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;141m[QUICK-MODE] Pulando '$step_name' (re-usando resultados existentes)\033[m"
			fi
			return 0
		fi
	fi

	# Verifica se etapa já foi completa
	if check_step "$step_name"; then
		if [ "$is_always_run" == "true" ]; then
			# Etapa de discovery: sempre re-executar para buscar novos alvos
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;148m[RE-SCAN] Re-executando '$step_name' para buscar novos alvos...\033[m"
			fi
		else
			# Etapa normal: pular se já completa
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Etapa '$step_name' já completa, pulando...\033[m"
			fi
			return 0
		fi
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
	local alive_domains="$1"

	# Valida entrada
	if [ ! -f "$alive_domains" ] || [ "$(cat $alive_domains | wc -l)" -lt "1" ]; then
		return
	fi

	local output_folder="$OUTFOLDER/subdomains"
	local waf_file="$output_folder/waf.txt"
	local checked_file="$output_folder/.waf_checked.txt"
	local new_domains_file="$output_folder/.new_waf_domains.txt"

	# Inicializa arquivo de checados se não existir
	[ ! -f "$checked_file" ] && touch "$checked_file"

	# Identifica domínios que ainda não foram checados
	if [ -f "$checked_file" ]; then
		# Re-scan: testar apenas novos domínios
		comm -13 <(sort "$checked_file") <(sort "$alive_domains") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Nenhum domínio novo para WAF detection\033[m"
			fi
			return 0
		fi

		if [ "$QUIET" == "True" ]; then
			echo -e -n "\033[38;5;81m[+] Detectando WAF (Incremental: $new_count novos) 🔎\033[m"
			wafw00f -i "$new_domains_file" -a -o "$output_folder/.waf_new.txt" > /dev/null 2>&1
			echo " ✅"
		else
			show_step_banner "🛡️" "DETECÇÃO WAF - Checando $new_count Novos Domínios" "198"
			echo -e "\033[38;5;148m[INCREMENTAL] Testando apenas $new_count novos domínios (vs $(cat "$alive_domains" | wc -l) total)\033[m"
			wafw00f -i "$new_domains_file" -a -o "$output_folder/.waf_new.txt"
		fi

		# Merge resultados
		if [ -f "$output_folder/.waf_new.txt" ]; then
			if [ -f "$waf_file" ]; then
				cat "$output_folder/.waf_new.txt" >> "$waf_file"
				sort -u "$waf_file" -o "$waf_file"
			else
				mv "$output_folder/.waf_new.txt" "$waf_file"
			fi
			rm -f "$output_folder/.waf_new.txt"
		fi

		# Atualiza lista de checados
		cat "$new_domains_file" >> "$checked_file"
		sort -u "$checked_file" -o "$checked_file"
		rm -f "$new_domains_file"

	else
		# Primeira execução: testar todos
		if [ "$QUIET" == "True" ]; then
			echo -e -n "\033[38;5;81m[+] Detectando WAF 🔎\033[m"
			wafw00f -i "$alive_domains" -a -o "$waf_file" > /dev/null 2>&1
			echo " ✅"
		else
			show_step_banner "🛡️" "DETECÇÃO WAF - Identificando Firewalls" "198"
			wafw00f -i "$alive_domains" -a -o "$waf_file"
		fi

		# Registra domínios checados
		cp "$alive_domains" "$checked_file"
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

	# Export env var para metabigor Go 1.25 compatibility
	export ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.25

	if [ "$QUIET" != "True" ]; then
		show_step_banner "🔍" "ENUMERAÇÃO ASN - Mapeando Redes" "198"
		echo $org | metabigor net --org 2>/dev/null > $output_folder/$org.txt.new
	else
		echo -e -n "\n\033[38;5;81m[+] Enumeração ASN 🔎\033[m"
		echo $org | metabigor net --org 2>/dev/null > $output_folder/$org.txt.new
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

		# NOVO: Timestamp tracking
		timestamp_and_track "$output_folder/$org.txt" "asn"
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

		# FILTRO RIGOROSO: Escape de pontos no domínio para regex
		domain_escaped=$(echo "$domain" | sed 's/\./\\./g')

		if [ "$QUIET" != "True" ]; then
			show_step_banner "✅" "TESTANDO DOMÍNIOS - Verificando Ativos" "148"
			echo -e "   \033[38;5;208m⚡ LIVE FEED:\033[m Novos domínios ativos aparecerão em tempo real\n"

			# Verifica se é primeira execução ou re-scan
			if [ -f "$output_folder/alive.txt" ]; then
				# Re-scan: mostrar [NEW] apenas para domínios realmente novos
				# FILTRO RIGOROSO: Apenas URLs que terminam exatamente com o domínio target (anti-bypass)
				cat $subdomains | httprobe | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" | while read line; do
					echo "$line" >> $output_folder/alive.txt.new
					if ! grep -Fxq "$line" "$output_folder/alive.txt" 2>/dev/null; then
						echo -e "\033[38;5;46m[NEW] $line\033[m"
					fi
				done
				cat $subdomains | httpx --silent --threads 300 | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" | while read line; do
					echo "$line" >> $output_folder/alive.txt.new
					if ! grep -Fxq "$line" "$output_folder/alive.txt" 2>/dev/null; then
						echo -e "\033[38;5;46m[NEW] $line\033[m"
					fi
				done
			else
				# Primeira execução: todos são novos
				cat $subdomains | httprobe | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" | while read line; do echo -e "\033[38;5;46m[NEW] $line\033[m"; echo "$line" >> $output_folder/alive.txt.new; done
				cat $subdomains | httpx --silent --threads 300 | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" | while read line; do echo -e "\033[38;5;46m[NEW] $line\033[m"; echo "$line" >> $output_folder/alive.txt.new; done
			fi
		else
			echo -e "\n\033[38;5;81m[+] Domínios Ativos 🔎\033[m"
			cat $subdomains | httprobe | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" >> $output_folder/alive.txt.new
			cat $subdomains | httpx --silent --threads 300 | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" >> $output_folder/alive.txt.new
		fi

		# Limpa e remove duplicatas dos novos resultados (verificação de arquivo vazio)
		if [ -f "$output_folder/alive.txt.new" ] && [ -s "$output_folder/alive.txt.new" ]; then
			sort -u $output_folder/alive.txt.new -o $output_folder/alive.txt.new
		else
			touch $output_folder/alive.txt.new
		fi

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

		# NOVO: Timestamp tracking
		timestamp_and_track "$output_folder/alive.txt" "alive_domain"
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
			show_step_banner "🎯" "ENUMERAÇÃO DE SUBDOMÍNIOS - Multi-Tool" "81"
			echo -e "   \033[38;5;240m→\033[m Salvando em: \033[38;5;198m$output_folder/subdomains.txt\033[m\n"
			echo -e "\033[38;5;81m>>>\033[38;5;141m Executando assetfinder 🔍\033[m"
			assetfinder $target | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/assetfinder $target | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando subfinder 🔍\033[m"
			subfinder -d $target -all -silent | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/subfinder --silent -d $target | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando crt.sh (Certificate Transparency) 🔍\033[m"
			curl -s "https://crt.sh/?q=%25.$target&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando amass 🔍\033[m"
			amass enum --passive -d $target | tee -a $output_folder/subdomains.txt.new || $GOPATH/bin/amass enum --passive -d $target | tee -a $output_folder/subdomains.txt.new
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando findomain 🔍\033[m"
			findomain -t $target -q -u $SCRIPTPATH/findomain-$target.txt 2>/dev/null || $GOPATH/bin/findomain -t $target -q -u $SCRIPTPATH/findomain-$target.txt 2>/dev/null
			[ -f "$SCRIPTPATH/findomain-$target.txt" ] && cat $SCRIPTPATH/findomain-$target.txt | tee -a $output_folder/subdomains.txt.new
			[ -f "$SCRIPTPATH/findomain-$target.txt" ] && rm $SCRIPTPATH/findomain-$target.txt
			echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando SubDomainizer 🔍\033[m"
			sublist3r -d $target -o $SCRIPTPATH/sublist3r-$domain.txt
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && cat $SCRIPTPATH/sublist3r-$domain.txt >> $output_folder/subdomains.txt.new
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && rm $SCRIPTPATH/sublist3r-$domain.txt
			knockpy -d $target --wordlist $wordlist --json --save $output_folder/knockpy/ --threads 5
			if [ "$GHAPIKEY" != "False" ]; then
				echo -e "\n\033[38;5;81m>>>\033[38;5;141m Executando Github-Subdomains 🔍\033[m"
				$SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/github-search/github-subdomains.py -t $GHAPIKEY -d $target | tee -a $output_folder/subdomains.txt.new
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
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando crt.sh 🔍\033[m"
			curl -s "https://crt.sh/?q=%25.$target&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u >> $output_folder/subdomains.txt.new
			echo " ✅"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando amass 🔍\033[m"
			amass enum --passive -d $target >> $output_folder/subdomains.txt.new || $GOPATH/bin/amass enum --passive -d $target >> $output_folder/subdomains.txt.new
			echo " ✅"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando findomain 🔍\033[m"
			findomain -t $target -q -u $SCRIPTPATH/findomain-$target.txt 2>/dev/null || $GOPATH/bin/findomain -t $target -q -u $SCRIPTPATH/findomain-$target.txt 2>/dev/null
			[ -f "$SCRIPTPATH/findomain-$target.txt" ] && cat $SCRIPTPATH/findomain-$target.txt >> $output_folder/subdomains.txt.new
			[ -f "$SCRIPTPATH/findomain-$target.txt" ] && rm $SCRIPTPATH/findomain-$target.txt
			echo " ✅"
			echo -e -n "\n\033[38;5;81m>>>\033[38;5;141m Executando sublist3r 🔍\033[m"
			sublist3r -d $target -o $SCRIPTPATH/sublist3r-$domain.txt > $SCRIPTPATH/temp.txt
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && cat $SCRIPTPATH/sublist3r-$domain.txt >> $output_folder/subdomains.txt.new
			[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && rm $SCRIPTPATH/sublist3r-$domain.txt
			[ -f "$SCRIPTPATH/temp.txt" ] && rm $SCRIPTPATH/temp.txt
			echo " ✅"
			echo -e -n "\n\033[38;5;81m>>>\033[38;5;141m Executando Knockpy 🔍\033[m"
			knockpy -d $target --wordlist $wordlist --json --save $output_folder/knockpy/ --threads 5 > $SCRIPTPATH/knocktemp
			[ -f "$SCRIPTPATH/knocktemp" ] && rm $SCRIPTPATH/knocktemp
			echo " ✅"
			if [ "$GHAPIKEY" != "False" ]; then
				echo -e -n "\033[38;5;81m>>>\033[38;5;141m Executando Github-Subdomains 🔍\033[m"
				$SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/github-search/github-subdomains.py -t $GHAPIKEY -d $target >> $output_folder/subdomains.txt.new
				echo " ✅"
			fi
		fi
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && cat $SCRIPTPATH/SubDomainizer$domain.txt >> $output_folder/subdomains.txt.new
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && rm $SCRIPTPATH/SubDomainizer$domain.txt

		# Processar resultados JSON do knockpy
		for a in $(ls $output_folder/knockpy/*.json 2>/dev/null); do
			python3 $SCRIPTPATH/scripts/knocktofile.py -f $a -o $SCRIPTPATH/knock.txt
		done
		[ -f "$SCRIPTPATH/knock.txt" ] && cat $SCRIPTPATH/knock.txt >> $output_folder/subdomains.txt.new
		[ -f "$SCRIPTPATH/knock.txt" ] && rm $SCRIPTPATH/knock.txt

		# Limpa resultados novos (remove wildcards, erros e emails)
		# FILTRO RIGOROSO: Apenas domínios que TERMINAM com $target ou SÃO exatamente $target
		cat $output_folder/subdomains.txt.new 2>/dev/null | grep -v "\*" | grep -v "error occurred" | grep -v "@" | grep -E "(^|\.)$target$" | sort -u > $SCRIPTPATH/temporary_clean.txt

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

		# NOVO: Timestamp tracking
		timestamp_and_track "$output_folder/subdomains.txt" "subdomain"
	fi
}


subdomainTakeover() {
	list="$1"
	output_folder="$2"

	# Valida entrada
	if [ ! -f "$list" ] || [ "$(cat $list | wc -l)" -lt "1" ]; then
		return
	fi

	[[ ! -d $output_folder ]] && mkdir -p $output_folder

	local takeover_file="$output_folder/takeover.txt"
	local previous_checked="$output_folder/.checked_subdomains.txt"
	local new_subdomains_file="$output_folder/.new_subdomains_to_check.txt"

	# Identifica subdomínios que ainda não foram checados
	if [ -f "$previous_checked" ]; then
		# Re-scan: testar apenas novos subdomínios
		comm -13 <(sort "$previous_checked") <(sort "$list") > "$new_subdomains_file"
		local new_count=$(cat "$new_subdomains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Nenhum subdomínio novo para checar takeover\033[m"
			fi
			return 0
		fi

		if [ "$QUIET" != "True" ]; then
			show_step_banner "⚠️" "SUBDOMAIN TAKEOVER - Checando $new_count Novos Domínios" "208"
			echo -e "\033[38;5;148m[INCREMENTAL] Testando apenas $new_count novos subdomínios (vs $(cat "$list" | wc -l) total)\033[m"
		else
			echo -e "\n\033[38;5;81m[+] Subdomain Takeover (Incremental: $new_count novos) 🔎\033[m"
		fi

		# Testa apenas novos subdomínios
		subjack -w "$new_subdomains_file" -t 100 -timeout 30 -o "$output_folder/.new_takeover.txt" -ssl 2>/dev/null || \
		$GOPATH/bin/subjack -w "$new_subdomains_file" -t 100 -timeout 30 -o "$output_folder/.new_takeover.txt" -ssl 2>/dev/null

		# Merge resultados novos com existentes
		if [ -f "$output_folder/.new_takeover.txt" ]; then
			if [ -f "$takeover_file" ]; then
				cat "$output_folder/.new_takeover.txt" >> "$takeover_file"
				sort -u "$takeover_file" -o "$takeover_file"
			else
				mv "$output_folder/.new_takeover.txt" "$takeover_file"
			fi
			rm -f "$output_folder/.new_takeover.txt"
		fi

		# Atualiza lista de checados
		cat "$new_subdomains_file" >> "$previous_checked"
		sort -u "$previous_checked" -o "$previous_checked"
		rm -f "$new_subdomains_file"

	else
		# Primeira execução: testar todos
		if [ "$QUIET" != "True" ]; then
			show_step_banner "⚠️" "SUBDOMAIN TAKEOVER - Caça a Vulneráveis" "208"
		else
			echo -e "\n\033[38;5;81m[+] Subdomain Takeover 🔎\033[m"
		fi

		subjack -w "$list" -t 100 -timeout 30 -o "$takeover_file" -ssl 2>/dev/null || \
		$GOPATH/bin/subjack -w "$list" -t 100 -timeout 30 -o "$takeover_file" -ssl 2>/dev/null

		# Registra subdomínios checados
		cp "$list" "$previous_checked"
	fi

	# Mostra resultados
	if [ -f "$takeover_file" ] && [ -s "$takeover_file" ]; then
		stofound="$(cat $takeover_file | wc -l)"
		echo -e "\033[38;5;208m[💰] $stofound domínios vulneráveis foram encontrados (\$500-\$2000 cada!)\033[m"

		if [ "$QUIET" != "True" ]; then
			echo -e "\033[38;5;148m[RESULTS] Detalhes em: $takeover_file\033[m"
			cat "$takeover_file"
		fi
	else
		echo -e "\033[38;5;198m[-] Nenhum domínio vulnerável a Subdomain Takeover\033[m"
	fi
}


dnsLookup() {
	domains="$1"
	output_folder="$2"

	# Valida entrada
	if [ ! -f "$domains" ] || [ "$(cat $domains | wc -l)" -lt "1" ]; then
		return
	fi

	[[ ! -d $output_folder/DNS ]] && mkdir -p $output_folder/DNS

	local dns_file="$output_folder/DNS/dns.txt"
	local ip_file="$output_folder/DNS/ip_only.txt"
	local checked_file="$output_folder/DNS/.dns_checked.txt"
	local new_domains_file="$output_folder/DNS/.new_dns_domains.txt"

	# Inicializa arquivo de checados se não existir
	[ ! -f "$checked_file" ] && touch "$checked_file"

	# Identifica subdomínios que ainda não tiveram DNS lookup
	if [ -f "$checked_file" ]; then
		# Re-scan: resolver apenas novos subdomínios
		comm -13 <(sort "$checked_file") <(sort "$domains") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Nenhum subdomínio novo para DNS lookup\033[m"
			fi
			return 0
		fi

		if [ "$QUIET" == "True" ]; then
			echo -e "\n\033[38;5;81m[+] DNS Lookup (Incremental: $new_count novos) 🔎\033[m"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Descobrindo IPs 🔍\033[m"
			dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/.dns_new.txt" > $SCRIPTPATH/temp 2>/dev/null || $GOPATH/bin/dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/.dns_new.txt" > $SCRIPTPATH/temp 2>/dev/null
			rm -f $SCRIPTPATH/temp
			echo " ✅"
		else
			show_step_banner "🌐" "DNS LOOKUP - Resolvendo $new_count Novos Subdomínios" "141"
			echo -e "\033[38;5;148m[INCREMENTAL] Resolvendo apenas $new_count novos subdomínios (vs $(cat "$domains" | wc -l) total)\033[m"
			echo -e "\033[38;5;81m>>>\033[38;5;141m Descobrindo IPs 🔍\033[38;5;148m"
			dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/.dns_new.txt" || $GOPATH/bin/dnsx -l "$new_domains_file" -resp -o "$output_folder/DNS/.dns_new.txt"
			echo -e "\033[m"
		fi

		# Merge resultados DNS
		if [ -f "$output_folder/DNS/.dns_new.txt" ]; then
			if [ -f "$dns_file" ]; then
				cat "$output_folder/DNS/.dns_new.txt" >> "$dns_file"
				sort -u "$dns_file" -o "$dns_file"
			else
				mv "$output_folder/DNS/.dns_new.txt" "$dns_file"
			fi
			rm -f "$output_folder/DNS/.dns_new.txt"
		fi

		# Atualiza lista de checados
		cat "$new_domains_file" >> "$checked_file"
		sort -u "$checked_file" -o "$checked_file"
		rm -f "$new_domains_file"

	else
		# Primeira execução: resolver todos os subdomínios
		if [ "$QUIET" == "True" ]; then
			echo -e "\n\033[38;5;81m[+] DNS Lookup 🔎\033[m"
			echo -e -n "\033[38;5;81m>>>\033[38;5;141m Descobrindo IPs 🔍\033[m"
			dnsx --silent -l "$domains" -resp -o "$dns_file" > $SCRIPTPATH/temp 2>/dev/null || $GOPATH/bin/dnsx --silent -l "$domains" -resp -o "$dns_file" > $SCRIPTPATH/temp 2>/dev/null
			rm -f $SCRIPTPATH/temp
			echo " ✅"
		else
			show_step_banner "🌐" "DNS LOOKUP - Resolução e Enumeração" "141"
			echo -e "\033[38;5;81m>>>\033[38;5;141m Descobrindo IPs 🔍\033[38;5;148m"
			dnsx --silent -l "$domains" -resp -o "$dns_file" || $GOPATH/bin/dnsx -l "$domains" -resp -o "$dns_file"
			echo -e "\033[m"
		fi

		# Registra subdomínios checados
		cp "$domains" "$checked_file"
	fi

	# Enumeração DNS adicional (dnsrecon, dnsenum) - sempre no domínio principal
	if [ "$QUIET" != "True" ]; then
		echo -e "\033[38;5;81m>>>\033[38;5;141m Enumeração DNS 🔍\033[m"
		echo -e "\033[38;5;228m[!] Executando dnsrecon (pode dar timeout em domínios protegidos)...\033[m"
		timeout 120 dnsrecon -d $domain -D $wordlist 2>&1 | grep -v "ERROR" | tee -a $output_folder/DNS/dnsrecon.txt || echo -e "\033[38;5;228m[!] dnsrecon timeout/erro (normal para alvos protegidos)\033[m"
		echo -e "\033[38;5;228m[!] Executando dnsenum (pode dar timeout em domínios protegidos)...\033[m"
		timeout 120 dnsenum $domain -f $wordlist -o $output_folder/DNS/dnsenum.xml 2>&1 | grep -v "query timed out" || echo -e "\033[38;5;228m[!] dnsenum timeout/erro (normal para alvos protegidos)\033[m"
	else
		echo -e -n "\033[38;5;81m>>>\033[38;5;141m Enumeração DNS 🔍\033[m"
		timeout 120 dnsrecon -d $domain -D $wordlist >> $output_folder/DNS/dnsrecon.txt 2>/dev/null || true
		timeout 120 dnsenum $domain -f $wordlist -o $output_folder/DNS/dnsenum.xml 2>/dev/null || true
		echo " ✅"
	fi

	# Processar IPs descobertos (com verificação de arquivo vazio)
	if [ -f "$dns_file" ] && [ -s "$dns_file" ]; then
		cat "$dns_file" | awk '{print $2}' | tr -d "[]" | grep -v "^$" >> "$ip_file"
		sort -u "$ip_file" -o "$ip_file" 2>/dev/null
	fi

	if [ -f "$ip_file" ] && [ -s "$ip_file" ]; then
		ipfound="$(cat "$ip_file" | wc -l)"
		echo -e "\033[38;5;198m[+] Encontrados \033[38;5;198m$ipfound\033[38;5;148m IPs\033[m"
	else
		echo -e "\033[38;5;228m[!] Nenhum IP descoberto (domínio pode estar protegido ou inacessível)\033[m"
	fi
	[ -f "$SCRIPTPATH/$domain\_ips.txt" ] && rm $SCRIPTPATH/$domain\_ips.txt
}


favAnalysis() {
	alive_domains="$1"
	output_folder="$2"

	# Valida entrada
	if [ ! -f "$alive_domains" ] || [ "$(cat $alive_domains | wc -l)" -lt "1" ]; then
		return
	fi

	local FAVOUT="$output_folder/favfreak"
	local analyzed_file="$output_folder/.favicon_analyzed.txt"
	local new_domains_file="$output_folder/.new_favicon_domains.txt"

	# Cria diretórios necessários
	[[ ! -d $output_folder ]] && mkdir -p $output_folder
	[[ ! -d $FAVOUT ]] && mkdir -p $FAVOUT

	# Inicializa arquivo de analisados se não existir
	[ ! -f "$analyzed_file" ] && touch "$analyzed_file"

	# Identifica domínios que ainda não foram analisados
	if [ -f "$analyzed_file" ]; then
		# Re-scan: analisar apenas novos domínios
		comm -13 <(sort "$analyzed_file") <(sort "$alive_domains") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Nenhum domínio novo para análise de favicon\033[m"
			fi
			return 0
		fi

		if [ "$QUIET" != "True" ]; then
			show_step_banner "🎨" "ANÁLISE FAVICON - Analisando $new_count Novos Domínios" "198"
			echo -e "\033[38;5;148m[INCREMENTAL] Analisando apenas $new_count novos domínios (vs $(cat "$alive_domains" | wc -l) total)\033[m"
			cat "$new_domains_file" | $SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/FavFreak/favfreak.py --shodan -o $FAVOUT
		else
			echo -e "\n\033[38;5;81m[+] Análise Favicon (Incremental: $new_count novos) 🔎\033[m"
			cat "$new_domains_file" | $SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/FavFreak/favfreak.py --shodan -o $FAVOUT > $SCRIPTPATH/tmpfavfreak 2>/dev/null
			rm -f $SCRIPTPATH/tmpfavfreak
		fi

		# Atualiza lista de analisados
		cat "$new_domains_file" >> "$analyzed_file"
		sort -u "$analyzed_file" -o "$analyzed_file"
		rm -f "$new_domains_file"

	else
		# Primeira execução: analisar todos
		if [ "$QUIET" != "True" ]; then
			show_step_banner "🎨" "ANÁLISE FAVICON - Hash Fingerprinting" "198"
			cat "$alive_domains" | $SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/FavFreak/favfreak.py --shodan -o $FAVOUT
		else
			echo -e "\n\033[38;5;81m[+] Análise Favicon 🔎\033[m"
			cat "$alive_domains" | $SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/FavFreak/favfreak.py --shodan -o $FAVOUT > $SCRIPTPATH/tmpfavfreak 2>/dev/null
			rm -f $SCRIPTPATH/tmpfavfreak
		fi

		# Registra domínios analisados
		cp "$alive_domains" "$analyzed_file"
	fi

	echo -e "\033[38;5;81m>>>\033[38;5;141m Todos os hashes salvos em \033[38;5;198m$output_folder/favfreak/*.txt\033[m"

	# Gera dorks do Shodan para todos os hashes (novos e existentes)
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

	for a in $(ls $FAVOUT 2>/dev/null); do
		hash=$(echo "$a" | tr -d "$SCRIPTPATH" | tr -d '/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' | tr -d '\' 2>/dev/null | cut -d '.' -f1 | sed -e 's/,//g')
		if [ "$QUIET" != "True" ]; then
			echo "org:"$ORG" http.favicon.hash:$hash" | tee -a $output_folder/shodan-manual.txt
		else
			echo "org:"$ORG" http.favicon.hash:$hash" >> $output_folder/shodan-manual.txt
		fi
	done

	if [ -e $output_folder/shodan-results.txt ]; then
		if [ "$(cat $output_folder/shodan-results.txt | wc -l)" == "0" ]; then
			rm $output_folder/shodan-results.txt
		fi
	fi
}


dirFuzz() {
	alive_domains_fuzz="$1"
	output_folder_fuzz="$2"
	if [ "$(cat $alive_domains_fuzz | wc -l)" -ge "1" ];then
		if [ "$QUIET" != "True" ]; then
			show_step_banner "📁" "FUZZING DE DIRETÓRIOS - Brute Force" "198"
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
			show_step_banner "🔍" "GOOGLE DORKS - Gerando Consultas" "198"
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
		show_step_banner "💻" "GITHUB DORKS - Buscando Secrets" "148"
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

	[[ ! -d $output_folder ]] && mkdir -p $output_folder
	[[ ! -d $output_folder/credstuff ]] && mkdir -p $output_folder/credstuff

	if [ "$domain" == "" ]; then
		return
	fi

	local cred_file="$output_folder/credstuff/credstuff.txt"
	local last_run_file="$output_folder/credstuff/.last_run_timestamp"
	local alive_tracker="$OUTFOLDER/.trackers/alive_domain_tracker.csv"
	local should_run=false

	# Verifica se deve executar
	if [ ! -f "$last_run_file" ]; then
		# Primeira execução
		should_run=true
	elif [ -f "$alive_tracker" ]; then
		# Verifica se novos domínios ativos foram descobertos desde última execução
		local last_run_timestamp=$(cat "$last_run_file")

		# Conta domínios descobertos após timestamp da última execução
		local new_domains_count=$(awk -F',' -v ts="$last_run_timestamp" '$2 > ts' "$alive_tracker" 2>/dev/null | wc -l)

		if [ "$new_domains_count" -gt 0 ]; then
			should_run=true
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;148m[INCREMENTAL] $new_domains_count novos domínios desde última busca - re-executando credstuff\033[m"
			fi
		else
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Nenhum domínio novo desde última execução de credstuff\033[m"
			fi
			should_run=false
		fi
	else
		# Sem tracker, executa por garantia
		should_run=true
	fi

	# Executa credstuff se necessário
	if [ "$should_run" = true ]; then
		if [ "$QUIET" != "True" ]; then
			show_step_banner "🔐" "CREDENTIAL STUFFING - Hunting Leaks" "148"
			$SCRIPTPATH/tools/CredStuff-Auxiliary/CredStuff_Auxiliary/main.sh $domain $len | tee -a "$cred_file"
		else
			echo -e "\n\033[1;36m[+] Cred Stuff 🔎\033[m"
			$SCRIPTPATH/tools/CredStuff-Auxiliary/CredStuff_Auxiliary/main.sh $domain $len >> "$cred_file"
		fi

		# Registra timestamp da execução
		date '+%Y-%m-%d %H:%M:%S' > "$last_run_file"

		if [ "$QUIET" != "True" ]; then
			echo -e "\033[38;5;148m[+] Resultados salvos em $cred_file\033[m"
		fi
	fi
}


screenshots() {
	alive_domains_screenshots="$1"
	out_screenshots="$2"

	# Valida entrada
	if [ ! -r "$alive_domains_screenshots" ] || [ "$(cat $alive_domains_screenshots | wc -l)" -lt "1" ]; then
		return
	fi

	local captured_file="$out_screenshots/.screenshot_captured.txt"
	local new_domains_file="$out_screenshots/.new_screenshot_domains.txt"

	# Cria diretório de saída
	[[ ! -d "$out_screenshots" ]] && mkdir -p "$out_screenshots"

	# Inicializa arquivo de capturados se não existir
	[ ! -f "$captured_file" ] && touch "$captured_file"

	# Identifica domínios que ainda não foram capturados
	if [ -f "$captured_file" ]; then
		# Re-scan: capturar apenas novos domínios
		comm -13 <(sort "$captured_file") <(sort "$alive_domains_screenshots") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			if [ "$QUIET" != "True" ]; then
				echo -e "\033[38;5;228m[SKIP] Nenhum domínio novo para capturar screenshots\033[m"
			fi
			return 0
		fi

		if [ "$QUIET" != "True" ]; then
			show_step_banner "📸" "SCREENSHOTS - Capturando $new_count Novos Domínios" "148"
			echo -e "\033[38;5;148m[INCREMENTAL] Capturando apenas $new_count novos domínios (vs $(cat "$alive_domains_screenshots" | wc -l) total)\033[m"
		else
			echo -e "\n\033[1;36m[+] Screenshots (Incremental: $new_count novos) 🔎\033[m"
		fi

		# Executar EyeWitness apenas nos novos domínios
		$SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/EyeWitness/Python/EyeWitness.py --web --no-prompt -f "$new_domains_file" -d "$out_screenshots" --selenium-log-path "$out_screenshots/selenium-log.txt" --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" 2>&1 | grep -v "Chrome WebDriver initialization error" | grep -v "Timed out receiving message from renderer" | grep -v "Stacktrace:" | grep -v "^#[0-9]" || true

		# Atualiza lista de capturados
		cat "$new_domains_file" >> "$captured_file"
		sort -u "$captured_file" -o "$captured_file"
		rm -f "$new_domains_file"

	else
		# Primeira execução: capturar todos
		if [ "$QUIET" != "True" ]; then
			show_step_banner "📸" "SCREENSHOTS - Capturando Páginas" "148"
		else
			echo -e "\n\033[1;36m[+] Screenshots 🔎\033[m"
		fi

		# Executar EyeWitness com tratamento de erros (timeouts de Chrome são esperados)
		$SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/EyeWitness/Python/EyeWitness.py --web --no-prompt -f "$alive_domains_screenshots" -d "$out_screenshots" --selenium-log-path "$out_screenshots/selenium-log.txt" --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" 2>&1 | grep -v "Chrome WebDriver initialization error" | grep -v "Timed out receiving message from renderer" | grep -v "Stacktrace:" | grep -v "^#[0-9]" || true

		# Registra domínios capturados
		cp "$alive_domains_screenshots" "$captured_file"
	fi

	echo -e "\033[38;5;148m[+] Screenshots concluídos (erros de timeout são normais e não afetam resultados)\033[m"
}


portscan() {
	portscan_domains="$1"
	ips="$2"
	output_folder="$3"
	if [ "$(cat $portscan_domains | wc -l)" -ge "1" ] && [ "$(cat $ips | wc -l)" -ge "1" ]; then
		[[ ! -d $output_folder ]] && mkdir $output_folder 2>/dev/null
		if [ "$QUIET" != "True" ]; then
			show_step_banner "🔌" "PORT SCAN - Mapeando Serviços" "148"
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
            show_step_banner "🔗" "DESCOBERTA DE LINKS - Crawling URLs" "228"
        else
            echo -e -n "\n\033[1;36m[+] Descoberta de Links 🔎\033[m"
        fi

        [[ ! -d "$output_folder" ]] && mkdir "$output_folder"
        [[ ! -d "$output_folder/hakrawler" ]] && mkdir "$output_folder/hakrawler" 2>/dev/null
        [[ ! -d "$output_folder/katana" ]] && mkdir "$output_folder/katana" 2>/dev/null
        [[ ! -d "$output_folder/waybackurls" ]] && mkdir "$output_folder/waybackurls" 2>/dev/null

        # Parallel execution para máxima performance (10-50x mais rápido)
        echo -e "\033[38;5;148m[PERFORMANCE] Executando crawlers em paralelo (20 threads)...\033[m"

        # Hakrawler paralelo
        cat "$alive_domains" | xargs -P 20 -I@ bash -c 'dnohttps=$(echo @ | cut -d "/" -f3-); echo @ | hakrawler -subs >> "'"$output_folder"'/hakrawler/$dnohttps.txt" 2>/dev/null'

        # Katana paralelo
        cat "$alive_domains" | xargs -P 20 -I@ bash -c 'dnohttps=$(echo @ | cut -d "/" -f3-); echo @ | katana -silent -jc >> "'"$output_folder"'/katana/$dnohttps.txt" 2>/dev/null'

        # Waybackurls paralelo com fallback
        cat "$alive_domains" | xargs -P 20 -I@ bash -c '
            dnohttps=$(echo @ | cut -d "/" -f3-)
            outfile="'"$output_folder"'/waybackurls/$dnohttps.txt"
            echo @ | waybackurls >> "$outfile" 2>/dev/null
            if [ ! -s "$outfile" ]; then
                timestamp=$(date +%s%3N)
                curl -s "https://web.archive.org/web/timemap/json?url=$dnohttps&matchType=prefix&collapse=urlkey&output=json&fl=original&filter=\!statuscode%3A%5B45%5D..&limit=10000&_=$timestamp" \
                | jq -r ".[1:][]|.[0]" 2>/dev/null | sort -u >> "$outfile"
            fi
        '

        cat "$output_folder/hakrawler/"*.txt 2>/dev/null | cut -d "]" -f2- | sed -e 's/^[ \t]*//' >> "$output_folder/all.txt" 2>/dev/null
        cat "$output_folder/katana/"*.txt 2>/dev/null | sed -e 's/^[ \t]*//' >> "$output_folder/all.txt" 2>/dev/null
        cat "$output_folder/waybackurls/"*.txt 2>/dev/null | sed -e 's/^[ \t]*//' >> "$output_folder/all.txt" 2>/dev/null

        # FILTRO RIGOROSO: Apenas URLs que terminam exatamente com o domínio target (anti-bypass)
        domain_escaped=$(echo "$domain" | sed 's/\./\\./g')
        cat "$output_folder/all.txt" 2>/dev/null | grep -E "https?://(([a-zA-Z0-9-]+\.)*${domain_escaped}|${domain_escaped})(/|:|$)" | sort -u -o "$output_folder/all.txt"

        if [ "$QUIET" == "True" ]; then
            echo " ✅"
        fi

        all="$(cat "$output_folder/all.txt" | wc -l)"
        echo -e "\033[35m[+] Encontrados \033[31m$all\033[35m links\033[m"

        # NOVO: Timestamp tracking
        timestamp_and_track "$output_folder/all.txt" "url"
    fi
}


endpointsEnumeration() {
	alive_domains="$1"
	output_folder="$2"

	if [ "$(cat $alive_domains | wc -l)" -ge "1" ]; then
		if [ "$QUIET" != "True" ]; then
			show_step_banner "📡" "ENUMERAÇÃO DE ENDPOINTS - Caça a Parâmetros" "141"
		else
			echo -e "\n\033[1;36m[+] Enumeração de Endpoints 🔎\033[m"
		fi
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[36m>>>\033[35m Extracting URLs 🔍\033[m"
		mkdir -p $output_folder/results
			xargs -a $alive_domains -I@ bash -c "cd $output_folder && $SCRIPTPATH/.venv/bin/paramspider -d @ -s 2>/dev/null" >> $output_folder/all.txt
		else
			echo -e -n "\n\033[36m>>>\033[35m Extracting URLs 🔍\033[m"
			xargs -a $alive_domains -I@ bash -c "cd $output_folder && $SCRIPTPATH/.venv/bin/paramspider -d @ -s 2>/dev/null" >> $output_folder/all.txt
			echo " ✅"
		fi
		# FILTRO RIGOROSO: Apenas URLs do domínio target
		domain_escaped=$(echo "$domain" | sed 's/\./\\./g')
		cat $output_folder/all.txt 2>/dev/null | grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | sort -u -o $output_folder/all.txt

		[[ ! -d $output_folder/js ]] && mkdir $output_folder/js
		echo -e "\n\033[36m>>>\033[35m Enumerating Javascript files 🔍\033[m"
		xargs -P 500 -a $DOMAINS -I@ bash -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 bash -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew' | grep -Eo "(http|https)://[^/\"].*\.js+" >> $output_folder/js/js.txt
		cat $alive_domains | sed 's|https\?://||' | cut -d'/' -f1 | sort -u | waybackurls | grep -iE '\.js' | grep -iEv '(\.jsp|\.json)' >> $output_folder/js/js.txt
		xargs -a $alive_domains -I@ bash -c 'getJS --url @ --complete 2>/dev/null' >> $output_folder/js/js.txt

		# FILTRO RIGOROSO: Apenas JS files do domínio target (remove CDNs externos)
		cat $output_folder/js/js.txt 2>/dev/null | grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | sort -u -o $output_folder/js/js.txt
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
			show_step_banner "🔥" "SCAN DE VULNERABILIDADES - Hunting Bugs" "198"
		else
			echo -e "\n\033[1;36m[+] Vulnerabilidades 🔎\033[m"
		fi
		echo -e "\n\033[36m[+] Finding vulnerabilities with Nuclei 🔍\033[m"
		[[ ! -d $HOME/nuclei-templates ]] && nuclei --update-templates
		[[ ! -d $output_folder ]] && mkdir -p $output_folder 2>/dev/null

		# INCREMENTAL TESTING: Testa novos alvos primeiro (alta prioridade)
		local new_targets_file="$OUTFOLDER/.trackers/new_targets_last_24h.txt"
		local tested_targets="$output_folder/.tested_targets.txt"
		local remaining_targets="$output_folder/.remaining_targets.txt"

		# Inicializa arquivo de alvos testados se não existir
		[ ! -f "$tested_targets" ] && touch "$tested_targets"

		# Identifica novos alvos (descobertos nas últimas 24h)
		if [ -f "$new_targets_file" ]; then
			local new_count=$(cat "$new_targets_file" | grep -v "^$" | wc -l)

			if [ "$new_count" -gt 0 ]; then
				echo -e "\033[38;5;208m"
				echo -e "╔══════════════════════════════════════════════════════════════╗"
				echo -e "   🎯  MODO INCREMENTAL ATIVADO                                 "
				echo -e "╚══════════════════════════════════════════════════════════════╝"
				echo -e "\033[38;5;148m[PRIORITY] Testando $new_count NOVOS alvos primeiro (alta densidade de bugs!)\033[m"
				echo -e "\033[38;5;228m[TIP] Estes alvos foram descobertos nas últimas 24h\033[m"
				echo -e "\033[m"

				# Testa apenas novos alvos com Nuclei
				nuclei -l "$new_targets_file" \
					-t $HOME/nuclei-templates/ \
					-rate-limit 150 \
					-bulk-size 25 \
					-c 25 \
					-timeout 10 \
					-retries 1 \
					-o "$output_folder/nuclei_new.txt" \
					--silent

				# Merge com resultados existentes
				if [ -f "$output_folder/nuclei_new.txt" ]; then
					cat "$output_folder/nuclei_new.txt" >> "$output_folder/nuclei.txt"
					sort -u "$output_folder/nuclei.txt" -o "$output_folder/nuclei.txt"
					rm -f "$output_folder/nuclei_new.txt"
				fi

				# Registra novos alvos como testados
				cat "$new_targets_file" >> "$tested_targets"
				sort -u "$tested_targets" -o "$tested_targets"

				echo -e "\033[38;5;148m[PRIORITY] Novos alvos testados com sucesso!\033[m\n"
			fi
		fi

		# Identifica alvos restantes (não testados ainda)
		comm -13 <(sort "$tested_targets") <(sort "$alive_domains") > "$remaining_targets"
		local remaining_count=$(cat "$remaining_targets" | grep -v "^$" | wc -l)

		if [ "$remaining_count" -gt 0 ]; then
			echo -e "\033[38;5;81m[FULL-SCAN] Agora testando $remaining_count alvos existentes (baixa prioridade)\033[m"
			echo -e "\033[38;5;228m[TIP] Você pode Ctrl+C agora se quiser focar apenas nos novos alvos\033[m"
			sleep 3  # Pausa 3 seg para usuário decidir

			# Testa alvos restantes
			nuclei -l "$remaining_targets" \
				-t $HOME/nuclei-templates/ \
				-tags cve,exposure,misconfig,takeover,sqli,xss,rce,lfi,ssrf \
				-severity critical,high,medium \
				-rate-limit 150 \
				-bulk-size 25 \
				-c 25 \
				-timeout 10 \
				-retries 1 \
				-o "$output_folder/nuclei_existing.txt" \
				--silent

			# Merge com resultados existentes
			if [ -f "$output_folder/nuclei_existing.txt" ]; then
				cat "$output_folder/nuclei_existing.txt" >> "$output_folder/nuclei.txt"
				sort -u "$output_folder/nuclei.txt" -o "$output_folder/nuclei.txt"
				rm -f "$output_folder/nuclei_existing.txt"
			fi

			# Registra alvos restantes como testados
			cat "$remaining_targets" >> "$tested_targets"
			sort -u "$tested_targets" -o "$tested_targets"
		else
			echo -e "\033[38;5;148m[COMPLETE] Todos os alvos já foram testados!\033[m"
		fi

		rm -f "$remaining_targets"

		# Mostra estatísticas
		local total_vulns=$(cat "$output_folder/nuclei.txt" 2>/dev/null | wc -l)
		echo -e "\033[38;5;148m[NUCLEI] Total de vulnerabilidades encontradas: \033[38;5;198m$total_vulns\033[m"
		echo -e "\n\033[36m>>>\033[35m Finding XSS 🤖\033[m"
		list="$OUTFOLDER/link-discovery/all.txt"
		[[ ! -d $output_folder/xss-discovery ]] && mkdir $output_folder/xss-discovery 2>/dev/null
		if [ "$QUIET" != "True" ]; then
			echo -e "\n\033[36m>>>\033[34m Finding XSS with Gxss🤖\033[m"
			cat $OUTFOLDER/link-discovery/all.txt | anti-burl | awk '{print $4}' | grep -E "^https?://" | Gxss -p XSS 2>/dev/null | sed '/^$/d' | tee -a $output_folder/xss-discovery/temppossíveis-xss.txt
		else
			echo -e -n "\n\033[36m>>>\033[34m Finding XSS with Gxss🤖\033[m"
			cat $OUTFOLDER/link-discovery/all.txt | anti-burl | awk '{print $4}' | grep -E "^https?://" | Gxss -p XSS 2>/dev/null >> $output_folder/xss-discovery/temppossíveis-xss.txt
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
			$SCRIPTPATH/.venv/bin/python3 $SCRIPTPATH/tools/XSStrike/xsstrike.py -u $a
		done
		echo -e "\n\033[36m>>>\033[34m Finding XSS with Dalfox🤖\033[m"
		gospider -S $OUTFOLDER/subdomains/alive.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe --skip-bav --silence | tee -a $output_folder/xss-discovery/xss.txt
	fi
	xssfound="$(cat $output_folder/xss-discovery/*.txt | wc -l)"
	echo -e "\033[1;33m[!] Encontrados \033[1;31m$xssfound\033[33m possíveis XSS\033[m"
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
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$lenopenredir\033[33m possíveis Open Redirects\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveis Open Redirects\033[m"
	fi

	echo -e "\n\033[36m>>>\033[35m Finding possíveis RCE 🤖\033[m"
	grepVuln "$rce_parameters" "$list" "$output_folder/rce.txt"
	if [ -e $output_folder/rce.txt ]; then
		lenrce="$(cat $output_folder/rce.txt | wc -l)"
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$lenrce\033[33m possíveis RCEs\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveis RCEs\033[m"
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
		echo -e "\033[1;33m[!] Encontrados \033[1;31m$lenlfi\033[33m possíveis LFIs\033[m"
	else
		echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveis LFIs\033[m"
	fi
	echo -e "\n\033[36m>>>\033[35m Finding possíveis SQLi 🤖\033[m"
	cat $DOMAINS | sort -u | waybackurls | gf sqli >> $output_folder/possíveis-sqli.txt
	if [ -e "$output_folder/possíveis-sqli.txt" ]; then
		sqlifound="$(cat $output_folder/possíveis-sqli.txt | wc -l)"
		if [ "$sqlifound" -ge "1" ]; then
			echo -e "\033[1;33m[!] Encontrados \033[1;31m$sqlifound\033[33m possíveis SQLi\033[m"
		else
			echo -e "\033[1;33m[!] Encontrados \033[1;31m0\033[33m possíveis SQLi\033[m"
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

while getopts ":d:w:t:g:s:q:o:f:D:P:Q:" ops; do
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
		Q)
			QUICK_MODE="True"
			;;
		:)
			if [ "${OPTARG}" == "q" ]; then
				QUIET="True"
			elif [ "${OPTARG}" == "f" ]; then
				FUZZ="True"
			elif [ "${OPTARG}" == "D" ]; then
				DIRFUZZ="True"
			elif [ "${OPTARG}" == "P" ]; then
				PORTSCAN="True"
			elif [ "${OPTARG}" == "Q" ]; then
				QUICK_MODE="True"
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

# Valores padrão para flags opcionais
[ -z "$FUZZ" ] && FUZZ="False"
[ -z "$DIRFUZZ" ] && DIRFUZZ="False"
[ -z "$PORTSCAN" ] && PORTSCAN="False"

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
check_recent_scan  # NOVO: Sugere quick mode se scan recente
show_banner
show_progress

# ╔═══════════════════════════════════════════════════════════════════════╗
# ║                         PIPELINE DE RECONHECIMENTO                    ║
# ╚═══════════════════════════════════════════════════════════════════════╝

run_step "asn_enum" asnEnum $domain $OUTFOLDER/asn

run_step "subdomain_enum" subdomainEnumeration $domain $OUTFOLDER/subdomains

run_step "organize_domains" organizeDomains $DOMAINS $OUTFOLDER/subdomains

run_step "dns_lookup" dnsLookup $DOMAINS $OUTFOLDER

run_step "check_active" checkActive $DOMAINS $OUTFOLDER/subdomains

run_step "waf_detect" wafDetect $OUTFOLDER/subdomains/alive.txt

run_step "subdomain_takeover" subdomainTakeover $DOMAINS $OUTFOLDER/subdomains/subdomain-takeover

run_step "favicon_analysis" favAnalysis $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/favicon-analysis

if [ "$DIRFUZZ" == "True" ]; then
	run_step "directory_fuzzing" dirFuzz $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/fuzz
fi

run_step "cred_stuff" credStuff 500 $OUTFOLDER/dorks

run_step "google_hacking" googleHacking $OUTFOLDER/dorks/google-dorks

run_step "github_dorks" ghDork $OUTFOLDER/dorks/github-dorks

run_step "screenshots" screenshots $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/domain-screenshots

if [ "$PORTSCAN" == "True" ]; then
	run_step "port_scanning" portscan $DOMAINS $OUTFOLDER/DNS/ip_only.txt $OUTFOLDER/portscan/
fi

run_step "link_discovery" linkDiscovery $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/link-discovery

run_step "endpoints_enum" endpointsEnumeration $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/link-discovery

run_step "vulnerability_scan" findVuln $OUTFOLDER/subdomains/alive.txt $OUTFOLDER/vuln

org="$(echo $domain | cut -d '.' -f1)"
if [ -e $OUTFOLDER/asn/$org.txt ]; then
	asn="$(cat $OUTFOLDER/asn/$org.txt | wc -l)"
else
	asn="0"
fi
subsfound="$([ -f "$DOMAINS" ] && cat $DOMAINS | wc -l || echo 0)"
subsalive="$([ -f "$OUTFOLDER/subdomains/alive.txt" ] && cat $OUTFOLDER/subdomains/alive.txt | wc -l || echo 0)"
if [ -e $OUTFOLDER/subdomains/subdomain-takeover/takeover.txt ]; then
	takeofound="$(cat $OUTFOLDER/subdomains/subdomain-takeover/takeover.txt | wc -l)"
fi
ips="$([ -f "$OUTFOLDER/DNS/ip_only.txt" ] && cat $OUTFOLDER/DNS/ip_only.txt | wc -l || echo 0)"
favfound="$([ -d "$OUTFOLDER/favicon-analysis/favfreak" ] && cat $OUTFOLDER/favicon-analysis/favfreak/*.txt 2>/dev/null | wc -l || echo 0)"
fuzzdir="$([ -d "$OUTFOLDER/fuzz" ] && ls $OUTFOLDER/fuzz 2>/dev/null | wc -l || echo 0)"
fuzzdirfound="$([ -d "$OUTFOLDER/fuzz" ] && cat $OUTFOLDER/fuzz/* 2>/dev/null | wc -l || echo 0)"
jsfound="$([ -f "$OUTFOLDER/link-discovery/js/js.txt" ] && cat $OUTFOLDER/link-discovery/js/js.txt | wc -l || echo 0)"
jsalive="$([ -f "$OUTFOLDER/link-discovery/js/AliveJS.txt" ] && cat $OUTFOLDER/link-discovery/js/AliveJS.txt | wc -l || echo 0)"
lfound="$([ -f "$OUTFOLDER/link-discovery/all.txt" ] && cat $OUTFOLDER/link-discovery/all.txt | wc -l || echo 0)"
foundvuln="$(($([ -d "$OUTFOLDER/vuln" ] && cat $OUTFOLDER/vuln/* 2>/dev/null | wc -l || echo 0)+$([ -d "$OUTFOLDER/vuln/xss-discovery" ] && cat $OUTFOLDER/vuln/xss-discovery/* 2>/dev/null | wc -l || echo 0)))"

# Mostrar resumo de novos alvos encontrados
if [ "$NEW_TARGETS_FOUND" -gt 0 ]; then
	echo -e "\n\033[38;5;148m[+] Encontrados \033[38;5;198m$NEW_TARGETS_FOUND\033[38;5;148m NOVOS alvos nesta execução!\033[m"
else
	echo -e "\n\033[38;5;228m[!] Nenhum novo alvo encontrado - todos os alvos já existiam de execuções anteriores.\033[m"
fi

echo -e "\033[38;5;198m====================================================================================================================\033[m"
echo -e "\033[38;5;198m====================\033[38;5;148m Resultados Finais \033[38;5;198m====================\033[m"
echo -e "\033[38;5;148m[+] ASNs Encontrados: \033[38;5;198m$asn\033[m"
echo -e "\033[38;5;148m[+] Subdomínios Encontrados: \033[38;5;198m$subsfound\033[m"
echo -e "\033[38;5;148m[+] Subdomínios Ativos Encontrados: \033[38;5;198m$subsalive\033[m"
if [ -e $OUTFOLDER/subdomains/subdomain-takeover/takeover.txt ] && [ "$(cat $OUTFOLDER/subdomains/subdomain-takeover/takeover.txt | wc -l)" -ge "1" ]; then
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

# NOVO: Gera arquivo de novos alvos para testing incremental
if [ -d "$OUTFOLDER/.trackers" ]; then
	new_targets_file=$(generate_new_targets_file 24)
	new_targets_count=$(cat "$new_targets_file" 2>/dev/null | wc -l)

	if [ "$new_targets_count" -gt 0 ]; then
		echo -e "\033[38;5;208m"
		echo -e "╔══════════════════════════════════════════════════════════════╗"
		echo -e "║  🎯  ALVOS PRIORITÁRIOS (Últimas 24h)                       ║"
		echo -e "╚══════════════════════════════════════════════════════════════╝"
		echo -e "\033[38;5;148m[PRIORITY] $new_targets_count novos alvos descobertos nas últimas 24h\033[m"
		echo -e "\033[38;5;148m[PRIORITY] Teste ESTES primeiro (maior densidade de bugs!):\033[m"
		echo -e "\033[38;5;81m   $new_targets_file\033[m"
		echo -e "\033[38;5;228m[TIP] Use: nuclei -l $new_targets_file -t ~/nuclei-templates/\033[m"
		echo -e "\033[m"
	fi
fi

echo -e "\033[38;5;148mBoa caçada! 🎯\033[m"
echo -e "\033[38;5;198m====================\033[38;5;148m CONCLUÍDO \033[38;5;198m====================\033[m"
echo -e "\033[38;5;198m====================================================================================================================\033[m"
