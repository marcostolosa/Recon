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

# +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
# |G|l|o|b|a|l| |V|a|r|i|a|b|l|e|s|
# +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+

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

# Steps that always run (discovery stages + incremental testing)
ALWAYS_RUN_STEPS=(
	"asn_enum"
	"subdomain_enum"
	"organize_domains"
	"subdomain_takeover"
	"check_active"
	"waf_detect"
	"link_discovery"
	"endpoints_enum"
)

# Monokai Color Palette
PINK='\033[38;5;198m'      # #F92672 - Highlights, titles
GREEN='\033[38;5;148m'     # #A6E22E - Success messages
YELLOW='\033[38;5;228m'    # #E6DB74 - Warnings, info
CYAN='\033[38;5;81m'       # #66D9EF - Secondary info
PURPLE='\033[38;5;141m'    # #AE81FF - Decorative
ORANGE='\033[38;5;208m'    # #FD971F - Critical alerts
RESET='\033[m'

NEW_TARGETS_FOUND=0

# +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
# |C|h|e|c|k|p|o|i|n|t| |F|u|n|c|t|i|o|n|s|
# +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+

init_checkpoint() {
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	if [ ! -f "$checkpoint_file" ]; then
		mkdir -p "$OUTFOLDER" 2>/dev/null
		echo "# CVE-Hunters Elite Checkpoint File" > "$checkpoint_file"
		echo "# Scan iniciado em: $(date '+%Y-%m-%d %H:%M:%S')" >> "$checkpoint_file"
		echo "# Alvo: $domain" >> "$checkpoint_file"
		echo "" >> "$checkpoint_file"
	fi
}

check_step() {
	local step_name="$1"
	local checkpoint_file="$OUTFOLDER/.checkpoint"

	if [ -f "$checkpoint_file" ]; then
		if grep -q "^${step_name}:completed:" "$checkpoint_file"; then
			return 0  # Step completed
		fi
	fi
	return 1  # Step not completed
}

mark_step_complete() {
	local step_name="$1"
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

	# Remove any existing entry for this step
	if [ -f "$checkpoint_file" ]; then
		sed -i "/^${step_name}:/d" "$checkpoint_file"
	fi

	# Add completed marker
	echo "${step_name}:completed:${timestamp}" >> "$checkpoint_file"
}

show_progress() {
	local checkpoint_file="$OUTFOLDER/.checkpoint"
	local total_steps=${#PIPELINE_STEPS[@]}
	local completed=0

	if [ -f "$checkpoint_file" ]; then
		completed=$(grep -c ":completed:" "$checkpoint_file" 2>/dev/null || echo "0")
	fi

	# Sanitize counters (remove non-numeric characters)
	completed=$(echo "$completed" | tr -d '\n\r' | sed 's/[^0-9]//g')
	[ -z "$completed" ] && completed=0

	# Calculate percentage (avoid division by zero)
	local percentage=0
	if [ "$total_steps" -gt 0 ]; then
		percentage=$((completed * 100 / total_steps))
	fi

	echo -e "${CYAN}📊 Progresso: ${PINK}${completed}/${total_steps}${CYAN} etapas (${PINK}${percentage}%${CYAN})${RESET}"
}

show_step_banner() {
	local step_number="$1"
	local step_name="$2"
	local emoji="$3"
	local color="${4:-$CYAN}"

	# Modern minimalist style - cleaner and faster to read
	echo -e ""
	echo -e "${color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
	echo -e "${color}${emoji} ${PINK}[${step_number}/17]${color} ${step_name}${RESET}"
	echo -e "${color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

check_recent_scan() {
	local scan_history="$OUTFOLDER/.scan_history"

	if [ ! -f "$scan_history" ]; then
		return 1
	fi

	# Get last scan timestamp
	local last_scan=$(tail -1 "$scan_history" | cut -d'|' -f1)

	if [ -z "$last_scan" ]; then
		return 1
	fi

	# Calculate hours since last scan (cross-platform)
	local now_epoch=$(date +%s)
	local last_epoch=0

	# Try GNU date (Linux)
	last_epoch=$(date -d "$last_scan" +%s 2>/dev/null) || \
	# Try BSD date (macOS)
	last_epoch=$(date -j -f "%Y-%m-%d %H:%M:%S" "$last_scan" +%s 2>/dev/null) || \
	return 1

	local hours_since=$(( (now_epoch - last_epoch) / 3600 ))

	# If scan was less than 6 hours ago, suggest quick mode
	if [ "$hours_since" -lt 6 ] && [ "$QUICK_MODE" != "True" ]; then
		echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
		echo -e "${ORANGE}⚡ OTIMIZAÇÃO SUGERIDA${RESET}"
		echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
		echo -e "${YELLOW}[!] Último scan foi há ${hours_since} horas${RESET}"
		echo -e "${GREEN}[TIP] Para re-rodar apenas testing (pular discovery), use:${RESET}"
		echo -e "    ${PINK}./recon_elite.sh -d $domain -w $wordlist -Q${RESET}"
		echo -e "${GREEN}[TIP] Quick mode economiza ~95 min re-usando descobertas existentes${RESET}"
		echo -e "${YELLOW}Continuando full scan em 5 segundos (Ctrl+C para cancelar)...${RESET}\n"
		sleep 5
	fi

	# Record this scan
	echo "$(date '+%Y-%m-%d %H:%M:%S')|${QUICK_MODE:-False}" >> "$scan_history"

	return 0
}

# +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
# |T|i|m|e|s|t|a|m|p|i|n|g| |F|u|n|c|t|i|o|n|s|
# +-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+

timestamp_and_track() {
	local file="$1"
	local label="$2"

	[ ! -f "$file" ] && return 0

	local base_dir=$(dirname "$file")
	local base_name=$(basename "$file")
	local archive_dir="$base_dir/.history"
	local tracker_dir="$OUTFOLDER/.trackers"
	local tracker_file="$tracker_dir/${label}_tracker.csv"

	# Create directories
	mkdir -p "$archive_dir" "$tracker_dir" 2>/dev/null

	# Create timestamped snapshot
	local timestamp=$(date '+%Y%m%d_%H%M%S')
	local datestamp=$(date '+%Y-%m-%d %H:%M:%S')
	cp "$file" "$archive_dir/${base_name}.${timestamp}" 2>/dev/null

	# Initialize CSV if doesn't exist
	if [ ! -f "$tracker_file" ]; then
		echo "item,first_seen,last_seen,status" > "$tracker_file"
	fi

	# Find previous snapshot
	local prev_file=$(ls -t "$archive_dir/${base_name}".* 2>/dev/null | sed -n '2p')

	if [ -n "$prev_file" ] && [ -f "$prev_file" ]; then
		# Identify new items
		comm -13 <(sort "$prev_file") <(sort "$file") > "$tracker_dir/.new_items.tmp"

		# Add new items to tracker
		while IFS= read -r item; do
			[ -z "$item" ] && continue
			echo "\"$item\",\"$datestamp\",\"$datestamp\",\"active\"" >> "$tracker_file"
		done < "$tracker_dir/.new_items.tmp"

		# Update last_seen for existing items
		comm -12 <(sort "$prev_file") <(sort "$file") > "$tracker_dir/.existing_items.tmp"
		while IFS= read -r item; do
			[ -z "$item" ] && continue
			# Escape special regex characters
			local escaped_item=$(echo "$item" | sed 's/[[\.*^$()+?{|]/\\&/g')
			sed -i "s|^\"$escaped_item\",\(.*\),\".*\",\(.*\)$|\"$escaped_item\",\1,\"$datestamp\",\2|" "$tracker_file" 2>/dev/null
		done < "$tracker_dir/.existing_items.tmp"

		# Cleanup temp files
		rm -f "$tracker_dir/.new_items.tmp" "$tracker_dir/.existing_items.tmp"
	else
		# First run - add all items
		while IFS= read -r item; do
			[ -z "$item" ] && continue
			echo "\"$item\",\"$datestamp\",\"$datestamp\",\"active\"" >> "$tracker_file"
		done < "$file"
	fi

	# Generate new_targets_last_24h.txt for Nuclei priority queue
	local new_targets_file="$tracker_dir/new_targets_last_24h.txt"
	local cutoff_date=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v-24H '+%Y-%m-%d %H:%M:%S' 2>/dev/null)

	if [ -n "$cutoff_date" ] && [ -f "$tracker_file" ]; then
		awk -F',' -v cutoff="$cutoff_date" '
			NR>1 && $2 > "\""cutoff"\"" {
				gsub(/"/, "", $1);
				print $1
			}
		' "$tracker_file" > "$new_targets_file" 2>/dev/null
	fi
}

# +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
# |M|e|r|g|e| |F|u|n|c|t|i|o|n|s|
# +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+

merge_results() {
	local new_file="$1"
	local target_file="$2"

	[ ! -f "$new_file" ] && return 0

	# Use anew if available, otherwise fall back to sort -u
	if command -v anew &>/dev/null; then
		local added=$(cat "$new_file" | anew "$target_file" | wc -l)
		echo "$added"
	else
		# Fallback: manual merge with sort -u
		if [ -f "$target_file" ]; then
			local old_count=$(cat "$target_file" | wc -l)
			cat "$new_file" "$target_file" | sort -u > "${target_file}.tmp"
			mv "${target_file}.tmp" "$target_file"
			local new_count=$(cat "$target_file" | wc -l)
			local added=$((new_count - old_count))
			echo "$added"
		else
			cp "$new_file" "$target_file"
			cat "$target_file" | wc -l
		fi
	fi
}

# +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
# |U|t|i|l|i|t|y| |F|u|n|c|t|i|o|n|s|
# +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+

printBanner() {
	echo -e "${GREEN}"
	echo -e "\t ██████╗██╗   ██╗███████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ███████╗"
	echo -e "\t██╔════╝██║   ██║██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝"
	echo -e "\t██║     ██║   ██║█████╗  █████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝███████╗"
	echo -e "\t██║     ╚██╗ ██╔╝██╔══╝  ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗╚════██║"
	echo -e "\t╚██████╗ ╚████╔╝ ███████╗      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║███████║"
	echo -e "\t ╚═════╝  ╚═══╝  ╚══════╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝"
	echo -e "${RESET}"
	echo -e "\t\t${PINK}🎯 RECON - Automated Bug Bounty Reconnaissance${RESET}"
	echo -e "\t\t${CYAN}Version 2.0 ${RESET}"
}

show_help() {
	echo -e "\n\t${PINK}Usage:${RESET} ${GREEN}./recon_elite.sh${RESET} ${PURPLE}[ -d domain ]${RESET} ${CYAN}[ -w wordlist.txt ]${RESET} ${YELLOW}[ options ]${RESET}"
	echo -e "\n\t${PINK}Required:${RESET}"
	echo -e "\t${PURPLE}-d${RESET}  | Your ${PINK}target domain${RESET}"
	echo -e "\t${CYAN}-w${RESET}  | Path to your ${CYAN}wordlist${RESET}"
	echo -e "\n\t${PINK}Optional:${RESET}"
	echo -e "\t${YELLOW}-g${RESET}  | GitHub ${YELLOW}API_KEY${RESET} (improves subdomain enum)"
	echo -e "\t${YELLOW}-s${RESET}  | Shodan ${YELLOW}API_KEY${RESET} ${ORANGE}(requires premium)${RESET}"
	echo -e "\t${GREEN}-o${RESET}  | Output folder (default: ./\$domain)"
	echo -e "\t${GREEN}-q${RESET}  | Quiet mode (minimal output)"
	echo -e "\t${GREEN}-f${RESET}  | Enable fuzzing mode (slower, finds confirmed vulns)"
	echo -e "\t${PINK}-Q${RESET}  | ${PINK}Quick Mode${RESET} - Skip discovery, only testing (fast re-scan)"
	echo -e "\n\t${YELLOW}[!] API Keys are optional but improve results${RESET}"
}

grepVuln() {
	local params=("${!1}")
	local input="$2"
	local output="$3"

	for pattern in "${params[@]}"; do
		if [ -n "$input" ]; then
			if [ "$QUIET" != "True" ]; then
				echo "$input" | grep -F "$pattern" | tee -a "$output"
			else
				echo "$input" | grep -F "$pattern" >> "$output"
			fi
		fi
	done
}

run_step() {
	local step_name="$1"
	shift
	local func_name="$1"
	shift
	local args=("$@")

	# Check if already completed (skip logic)
	if check_step "$step_name"; then
		# Check if this step is in ALWAYS_RUN_STEPS
		local is_always_run=0
		for always_step in "${ALWAYS_RUN_STEPS[@]}"; do
			if [ "$always_step" == "$step_name" ]; then
				is_always_run=1
				break
			fi
		done

		# Skip if Quick Mode and this is a discovery step
		if [ "$QUICK_MODE" == "True" ] && [ "$is_always_run" -eq 1 ]; then
			echo -e "${CYAN}[QUICK-MODE] Pulando '${step_name}' (re-usando resultados existentes)${RESET}"
			return 0
		fi

		# Regular skip message for completed steps
		if [ "$is_always_run" -eq 0 ]; then
			echo -e "${YELLOW}[⏭️ ] Etapa '${step_name}' já completa, pulando...${RESET}"
			return 0
		fi
	fi

	# Run the function
	"$func_name" "${args[@]}"

	# Mark as complete
	mark_step_complete "$step_name"

	# Show progress
	show_progress
}

# +-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
# |A|S|N| |E|n|u|m|e|r|a|t|i|o|n|
# +-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+

asnEnum() {
	local subdomain="$1"
	local output_folder="$2"

	[[ ! -d "$output_folder" ]] && mkdir -p "$output_folder" 2>/dev/null

	local org="$(echo "$domain" | cut -d '.' -f1)"

	if [ "$QUIET" != "True" ]; then
		show_step_banner "1" "ASN ENUMERATION - Mapeando Redes" "🔍" "$PINK"
		# Export env var for metabigor Go 1.25+ compatibility
		export ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.25
		echo "$org" | metabigor net --org 2>/dev/null | tee "$output_folder/$org.txt.new"
	else
		echo -e "${CYAN}[+] ASN Enumeration 🔎${RESET}"
		export ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.25
		echo "$org" | metabigor net --org 2>/dev/null > "$output_folder/$org.txt.new"
	fi

	# Merge results intelligently
	if [ -f "$output_folder/$org.txt" ]; then
		local added=$(merge_results "$output_folder/$org.txt.new" "$output_folder/$org.txt")
		echo -e "${GREEN}[+] Adicionados ${PINK}$added${GREEN} novos ASNs${RESET}"
	else
		mv "$output_folder/$org.txt.new" "$output_folder/$org.txt" 2>/dev/null
	fi

	# Cleanup
	rm -f "$output_folder/$org.txt.new"

	# Count and display
	if [ -f "$output_folder/$org.txt" ]; then
		sort -u "$output_folder/$org.txt" -o "$output_folder/$org.txt"
		local asns=$(cat "$output_folder/$org.txt" | wc -l)
		echo -e "${GREEN}[!] Total: ${PINK}$asns${GREEN} ASNs${RESET}"

		# Timestamp tracking
		timestamp_and_track "$output_folder/$org.txt" "asn"
	else
		echo -e "${YELLOW}[!] Nenhum ASN encontrado${RESET}"
	fi
}

# +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
# |S|u|b|d|o|m|a|i|n| |E|n|u|m|e|r|a|t|i|o|n|
# +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+

subdomainEnumeration() {
	local target="$1"
	local output_folder="$2"

	[ -z "$target" ] || [ -z "$output_folder" ] && return 1

	[[ ! -d "$output_folder" ]] && mkdir -p "$output_folder" 2>/dev/null
	[[ ! -d "$output_folder/knockpy" ]] && mkdir -p "$output_folder/knockpy" 2>/dev/null

	# Remove old .new file
	rm -f "$output_folder/subdomains.txt.new"

	if [ "$QUIET" != "True" ]; then
		show_step_banner "2" "SUBDOMAIN ENUMERATION - Multi-Tool (10 Sources)" "🎯" "$PINK"
		echo -e "${YELLOW}[!] All subdomains will be saved in ${PINK}$output_folder/subdomains.txt${RESET}"

		echo -e "${CYAN}>>>${PURPLE} Running assetfinder 🔍${RESET}"
		assetfinder "$target" 2>/dev/null | tee -a "$output_folder/subdomains.txt.new" || \
		$GOPATH/bin/assetfinder "$target" 2>/dev/null | tee -a "$output_folder/subdomains.txt.new"

		echo -e "\n${CYAN}>>>${PURPLE} Running subfinder 🔍${RESET}"
		subfinder --silent -d "$target" 2>/dev/null | tee -a "$output_folder/subdomains.txt.new" || \
		$GOPATH/bin/subfinder --silent -d "$target" 2>/dev/null | tee -a "$output_folder/subdomains.txt.new"

		echo -e "\n${CYAN}>>>${PURPLE} Running amass (passive) 🔍${RESET}"
		export GO111MODULE=auto
		amass enum --passive -d "$target" 2>/dev/null | tee -a "$output_folder/subdomains.txt.new" || \
		$GOPATH/bin/amass enum --passive -d "$target" 2>/dev/null | tee -a "$output_folder/subdomains.txt.new"

		echo -e "\n${CYAN}>>>${PURPLE} Getting Subdomains from RapidDNS.io 🔍${RESET}"
		timeout 30 curl -s "https://rapiddns.io/subdomain/$target?full=1#result" 2>/dev/null | \
		grep "<td><a" | cut -d '"' -f 2 | grep -E "^http" | cut -d '/' -f3 | sed 's/#results//g' | \
		sort -u | tee -a "$output_folder/subdomains.txt.new"

		echo -e "\n${CYAN}>>>${PURPLE} Getting Subdomains from Riddler.io 🔍${RESET}"
		timeout 30 curl -s "https://riddler.io/search/exportcsv?q=pld:$target" 2>/dev/null | \
		grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee -a "$output_folder/subdomains.txt.new"

		echo -e "\n${CYAN}>>>${PURPLE} Getting Subdomains from SecurityTrails 🔍${RESET}"
		timeout 30 curl -s "https://securitytrails.com/list/apex_domain/$domain" 2>/dev/null | \
		grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep "\.$domain" | \
		sort -u | tee -a "$output_folder/subdomains.txt.new"

		# NEW: Certificate Transparency (crt.sh)
		echo -e "\n${CYAN}>>>${PURPLE} Running crt.sh (Certificate Transparency) 🔍${RESET}"
		timeout 30 curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | \
		jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | tee -a "$output_folder/subdomains.txt.new"

		echo -e "\n${CYAN}>>>${PURPLE} Running findomain 🔍${RESET}"
		findomain -t "$target" -q -u "$SCRIPTPATH/findomain-$target.txt" 2>/dev/null || \
		$GOPATH/bin/findomain -t "$target" -q -u "$SCRIPTPATH/findomain-$target.txt" 2>/dev/null
		[ -f "$SCRIPTPATH/findomain-$target.txt" ] && cat "$SCRIPTPATH/findomain-$target.txt" | tee -a "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/findomain-$target.txt" ] && rm "$SCRIPTPATH/findomain-$target.txt"

		echo -e "\n${CYAN}>>>${PURPLE} Running SubDomainizer 🔍${RESET}"
		python3 "$SCRIPTPATH/tools/SubDomainizer.py" -u "$target" -o "$SCRIPTPATH/SubDomainizer$domain.txt" 2>/dev/null | tee "$OUTFOLDER/SubDomainizer-$domain.txt" || true
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && cat "$SCRIPTPATH/SubDomainizer$domain.txt" >> "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && rm "$SCRIPTPATH/SubDomainizer$domain.txt"

		echo -e "\n${CYAN}>>>${PURPLE} Running sublist3r 🔍${RESET}"
		sublist3r -d "$target" -o "$SCRIPTPATH/sublist3r-$domain.txt" 2>/dev/null
		[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && cat "$SCRIPTPATH/sublist3r-$domain.txt" >> "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && rm "$SCRIPTPATH/sublist3r-$domain.txt"

		echo -e "\n${CYAN}>>>${PURPLE} Running knockpy 🔍${RESET}"
		knockpy -d "$target" -w "$wordlist" -o "$output_folder/knockpy/" -t 5 2>/dev/null || true

		# GitHub subdomain search (requires API key)
		if [ "$GHAPIKEY" != "False" ]; then
			echo -e "\n${CYAN}>>>${PURPLE} Running Github-Subdomains 🔍${RESET}"
			python3 "$SCRIPTPATH/tools/github-search/github-subdomains.py" -t "$GHAPIKEY" -d "$target" 2>/dev/null | \
			tee -a "$output_folder/subdomains.txt.new"
		fi
	else
		# QUIET MODE
		echo -e "${CYAN}[+] Subdomain Enumeration 🔎${RESET}"
		echo -e "${YELLOW}[!] All subdomains will be saved in ${PINK}$output_folder/subdomains.txt${RESET}"

		echo -n -e "${CYAN}>>> assetfinder${RESET}"
		assetfinder "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new" || \
		$GOPATH/bin/assetfinder "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> subfinder${RESET}"
		subfinder --silent -d "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new" || \
		$GOPATH/bin/subfinder --silent -d "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> amass${RESET}"
		export GO111MODULE=auto
		amass enum --passive -d "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new" || \
		$GOPATH/bin/amass enum --passive -d "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> RapidDNS.io${RESET}"
		timeout 30 curl -s "https://rapiddns.io/subdomain/$target?full=1#result" 2>/dev/null | \
		grep "<td><a" | cut -d '"' -f 2 | grep -E "^http" | cut -d '/' -f3 | sed 's/#results//g' | \
		sort -u >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> Riddler.io${RESET}"
		timeout 30 curl -s "https://riddler.io/search/exportcsv?q=pld:$target" 2>/dev/null | \
		grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> SecurityTrails${RESET}"
		timeout 30 curl -s "https://securitytrails.com/list/apex_domain/$domain" 2>/dev/null | \
		grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep "\.$domain" | \
		sort -u >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> crt.sh${RESET}"
		timeout 30 curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | \
		jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u >> "$output_folder/subdomains.txt.new"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> findomain${RESET}"
		findomain -t "$target" -q -u "$SCRIPTPATH/findomain-$target.txt" 2>/dev/null || \
		$GOPATH/bin/findomain -t "$target" -q -u "$SCRIPTPATH/findomain-$target.txt" 2>/dev/null
		[ -f "$SCRIPTPATH/findomain-$target.txt" ] && cat "$SCRIPTPATH/findomain-$target.txt" >> "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/findomain-$target.txt" ] && rm "$SCRIPTPATH/findomain-$target.txt"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> SubDomainizer${RESET}"
		python3 "$SCRIPTPATH/tools/SubDomainizer.py" -u "$target" -o "$SCRIPTPATH/SubDomainizer$domain.txt" 2>/dev/null >/dev/null || true
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && cat "$SCRIPTPATH/SubDomainizer$domain.txt" >> "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/SubDomainizer$domain.txt" ] && rm "$SCRIPTPATH/SubDomainizer$domain.txt"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> sublist3r${RESET}"
		sublist3r -d "$target" -o "$SCRIPTPATH/sublist3r-$domain.txt" 2>/dev/null >/dev/null
		[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && cat "$SCRIPTPATH/sublist3r-$domain.txt" >> "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/sublist3r-$domain.txt" ] && rm "$SCRIPTPATH/sublist3r-$domain.txt"
		echo -e " ${GREEN}✅${RESET}"

		echo -n -e "${CYAN}>>> knockpy${RESET}"
		knockpy -d "$target" -w "$wordlist" -o "$output_folder/knockpy/" -t 5 2>/dev/null >/dev/null || true
		echo -e " ${GREEN}✅${RESET}"

		if [ "$GHAPIKEY" != "False" ]; then
			echo -n -e "${CYAN}>>> github-subdomains${RESET}"
			python3 "$SCRIPTPATH/tools/github-search/github-subdomains.py" -t "$GHAPIKEY" -d "$target" 2>/dev/null >> "$output_folder/subdomains.txt.new"
			echo -e " ${GREEN}✅${RESET}"
		fi
	fi

	# Process knockpy results
	if [ -d "$output_folder/knockpy" ]; then
		for knock_file in "$output_folder/knockpy"/*; do
			[ -f "$knock_file" ] || continue
			if [ -f "$SCRIPTPATH/scripts/knocktofile.py" ]; then
				python3 "$SCRIPTPATH/scripts/knocktofile.py" -f "$knock_file" -o "$SCRIPTPATH/knock.txt" 2>/dev/null || true
			fi
		done
		[ -f "$SCRIPTPATH/knock.txt" ] && cat "$SCRIPTPATH/knock.txt" >> "$output_folder/subdomains.txt.new"
		[ -f "$SCRIPTPATH/knock.txt" ] && rm "$SCRIPTPATH/knock.txt"
	fi

	# Clean results (remove wildcards and error messages)
	if [ -f "$output_folder/subdomains.txt.new" ]; then
		grep -v "\*" "$output_folder/subdomains.txt.new" | \
		grep -v "error occurred" | \
		grep -v "HTTPSConnectionPool" | \
		grep -v "^$" | \
		# FIX #8: Strict scope filtering
		grep -E "(^|\.)$target$" | \
		sort -u > "$SCRIPTPATH/temporary_subs.txt"

		# Merge with existing file
		if [ -f "$output_folder/subdomains.txt" ]; then
			local added=$(merge_results "$SCRIPTPATH/temporary_subs.txt" "$output_folder/subdomains.txt")
			echo -e "${GREEN}[+] Adicionados ${PINK}$added${GREEN} novos subdomínios${RESET}"
		else
			mv "$SCRIPTPATH/temporary_subs.txt" "$output_folder/subdomains.txt"
		fi

		rm -f "$SCRIPTPATH/temporary_subs.txt" "$output_folder/subdomains.txt.new"
	fi

	# Count and display
	if [ -f "$output_folder/subdomains.txt" ]; then
		local total=$(cat "$output_folder/subdomains.txt" | wc -l)
		echo -e "${GREEN}[!] Total: ${PINK}$total${GREEN} subdomínios${RESET}"

		# Timestamp tracking
		timestamp_and_track "$output_folder/subdomains.txt" "subdomain"
	fi
}

# +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
# |O|r|g|a|n|i|z|i|n|g| |D|o|m|a|i|n|s|
# +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

organizeDomains() {
	local domains="$1"
	local output_folder="$2"
	local ldout="$output_folder/level-domains.txt"

	if [ ! -f "$domains" ] || [ ! -s "$domains" ]; then
		echo -e "${YELLOW}[!] Nenhum subdomínio para organizar${RESET}"
		return 0
	fi

	show_step_banner "3" "ORGANIZANDO DOMÍNIOS - Categorização por Nível" "📊" "$CYAN"

	echo -e "${PINK}[+] Organizando domínios por nível...${RESET}"

	# Remove old file
	rm -f "$ldout"

	# 2nd level domains
	echo "[+] Finding 2nd level domains..." >> "$ldout"
	grep -E '^([a-z0-9]+-?)+\.[^.]+$' "$domains" | sort -u | tee -a "$ldout" >/dev/null

	# 3rd level domains
	echo "[+] Finding 3rd level domains..." >> "$ldout"
	grep -E '^([a-z0-9]+-?)+\.([a-z0-9]+-?)+\.[^.]+$' "$domains" | sort -u | tee -a "$ldout" >/dev/null

	# 4th+ level domains
	echo "[+] Finding 4th level domains or higher..." >> "$ldout"
	grep -E '^([a-z0-9]+-?)+\.([a-z0-9]+-?)+\.([a-z0-9]+-?)+\.[^.]+' "$domains" | sort -u | tee -a "$ldout" >/dev/null

	echo -e "${GREEN}[!] Done. Output saved in ${PINK}$ldout${RESET}"
}

# +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
# |S|u|b|d|o|m|a|i|n| |T|a|k|e|o|v|e|r|
# +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+

subdomainTakeover() {
	local list="$1"
	local output_folder="$2"

	if [ ! -f "$list" ] || [ ! -s "$list" ]; then
		echo -e "${YELLOW}[!] Nenhum subdomínio para testar takeover${RESET}"
		return 0
	fi

	[[ ! -d "$output_folder" ]] && mkdir -p "$output_folder" 2>/dev/null

	show_step_banner "4" "SUBDOMAIN TAKEOVER - Caçando Vulneráveis" "⚠️ " "$ORANGE"

	# Incremental takeover testing
	local previous_checked="$output_folder/.checked_subdomains.txt"
	local new_subdomains_file="$output_folder/.new_subdomains.txt"
	local takeover_file="$output_folder/takeover.txt"

	# Identify new subdomains not yet checked
	if [ -f "$previous_checked" ]; then
		comm -13 <(sort "$previous_checked") <(sort "$list") > "$new_subdomains_file"
		local new_count=$(cat "$new_subdomains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			echo -e "${CYAN}[SKIP] Nenhum subdomínio novo para checar takeover${RESET}"
			return 0
		fi

		echo -e "${CYAN}[INCREMENTAL] Testando apenas ${PINK}$new_count${CYAN} novos subdomínios${RESET}"
		subjack -w "$new_subdomains_file" -t 100 -timeout 30 -o "$output_folder/.new_takeover.txt" -ssl 2>/dev/null || \
		$GOPATH/bin/subjack -w "$new_subdomains_file" -t 100 -timeout 30 -o "$output_folder/.new_takeover.txt" -ssl 2>/dev/null

		# Merge new results with existing
		if [ -f "$output_folder/.new_takeover.txt" ]; then
			cat "$output_folder/.new_takeover.txt" >> "$takeover_file"
			rm "$output_folder/.new_takeover.txt"
		fi

		# Update checked list
		cat "$new_subdomains_file" >> "$previous_checked"
		sort -u "$previous_checked" -o "$previous_checked"
		rm "$new_subdomains_file"
	else
		# First run - test all
		echo -e "${CYAN}[FULL-SCAN] Testando todos os subdomínios${RESET}"
		subjack -w "$list" -t 100 -timeout 30 -o "$takeover_file" -ssl 2>/dev/null || \
		$GOPATH/bin/subjack -w "$list" -t 100 -timeout 30 -o "$takeover_file" -ssl 2>/dev/null

		# Create checked list
		cp "$list" "$previous_checked"
	fi

	# Display results
	if [ -f "$takeover_file" ] && [ -s "$takeover_file" ]; then
		sort -u "$takeover_file" -o "$takeover_file"
		local stofound=$(cat "$takeover_file" | wc -l)
		echo -e "${GREEN}[+] ${PINK}$stofound${GREEN} domínios vulneráveis encontrados${RESET}"
	else
		echo -e "${YELLOW}[-] Nenhum domínio vulnerável a Subdomain Takeover${RESET}"
	fi
}

# +-+-+-+ +-+-+-+-+-+-+
# |D|N|S| |L|o|o|k|u|p|
# +-+-+-+ +-+-+-+-+-+-+

dnsLookup() {
	local domains="$1"
	local output_folder="$2"

	[[ ! -d "$output_folder/DNS" ]] && mkdir -p "$output_folder/DNS" 2>/dev/null

	if [ ! -f "$domains" ] || [ ! -s "$domains" ]; then
		echo -e "${YELLOW}[!] Nenhum domínio para DNS lookup${RESET}"
		return 0
	fi

	show_step_banner "5" "DNS LOOKUP - Resolução e Enumeração" "🌐" "$CYAN"

	# Incremental DNS lookup
	local previous_checked="$output_folder/DNS/.dns_checked.txt"
	local new_domains_file="$output_folder/DNS/.new_domains.txt"

	# Identify new domains
	if [ -f "$previous_checked" ]; then
		comm -13 <(sort "$previous_checked") <(sort "$domains") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			echo -e "${CYAN}[SKIP] Nenhum domínio novo para DNS lookup${RESET}"
			# Still run dnsrecon/dnsenum on main domain
		else
			echo -e "${CYAN}[INCREMENTAL] Resolvendo apenas ${PINK}$new_count${CYAN} novos domínios${RESET}"

			if [ "$QUIET" != "True" ]; then
				echo -e "${CYAN}>>>${PURPLE} Discovering IPs 🔍${RESET}"
				dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/dns.txt.new" 2>/dev/null || \
				$GOPATH/bin/dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/dns.txt.new" 2>/dev/null
			else
				echo -n -e "${CYAN}>>> Discovering IPs 🔍${RESET}"
				dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/dns.txt.new" 2>/dev/null || \
				$GOPATH/bin/dnsx --silent -l "$new_domains_file" -resp -o "$output_folder/DNS/dns.txt.new" 2>/dev/null
				echo -e " ${GREEN}✅${RESET}"
			fi

			# Merge results
			if [ -f "$output_folder/DNS/dns.txt.new" ]; then
				cat "$output_folder/DNS/dns.txt.new" >> "$output_folder/DNS/dns.txt"
				rm "$output_folder/DNS/dns.txt.new"
			fi

			# Update checked list
			cat "$new_domains_file" >> "$previous_checked"
			sort -u "$previous_checked" -o "$previous_checked"
			rm "$new_domains_file"
		fi
	else
		# First run - resolve all
		if [ "$QUIET" != "True" ]; then
			echo -e "${CYAN}>>>${PURPLE} Discovering IPs 🔍${RESET}"
			dnsx --silent -l "$domains" -resp -o "$output_folder/DNS/dns.txt" 2>/dev/null || \
			$GOPATH/bin/dnsx --silent -l "$domains" -resp -o "$output_folder/DNS/dns.txt" 2>/dev/null
		else
			echo -n -e "${CYAN}>>> Discovering IPs 🔍${RESET}"
			dnsx --silent -l "$domains" -resp -o "$output_folder/DNS/dns.txt" 2>/dev/null || \
			$GOPATH/bin/dnsx --silent -l "$domains" -resp -o "$output_folder/DNS/dns.txt" 2>/dev/null
			echo -e " ${GREEN}✅${RESET}"
		fi

		# Create checked list
		cp "$domains" "$previous_checked"
	fi

	# DNS enumeration (always run on main domain)
	if [ "$QUIET" != "True" ]; then
		echo -e "${CYAN}>>>${PURPLE} DNS enumeration 🔍${RESET}"
		# FIX #9 & #12: Add timeout and filter errors
		timeout 120 dnsrecon -d "$domain" -D "$wordlist" 2>&1 | grep -v "ERROR" | grep -v "query timed out" | tee -a "$output_folder/DNS/dnsrecon.txt" || true
		timeout 120 dnsenum "$domain" -f "$wordlist" -o "$output_folder/DNS/dnsenum.xml" 2>&1 | grep -v "query timed out" | grep -v "ERROR" || true
	else
		echo -n -e "${CYAN}>>> DNS enumeration 🔍${RESET}"
		timeout 120 dnsrecon -d "$domain" -D "$wordlist" 2>&1 | grep -v "ERROR" | grep -v "query timed out" >> "$output_folder/DNS/dnsrecon.txt" 2>/dev/null || true
		timeout 120 dnsenum "$domain" -f "$wordlist" -o "$output_folder/DNS/dnsenum.xml" 2>&1 | grep -v "query timed out" | grep -v "ERROR" >/dev/null 2>&1 || true
		echo -e " ${GREEN}✅${RESET}"
	fi

	# Extract IPs from DNS results
	if [ -f "$output_folder/DNS/dns.txt" ] && [ -s "$output_folder/DNS/dns.txt" ]; then
		cat "$output_folder/DNS/dns.txt" | awk '{print $2}' | tr -d "[]" | grep -v "^$" >> "$output_folder/DNS/ip_only.txt"
		sort -u "$output_folder/DNS/ip_only.txt" -o "$output_folder/DNS/ip_only.txt" 2>/dev/null

		local ipfound=$(cat "$output_folder/DNS/ip_only.txt" | wc -l)
		echo -e "${GREEN}[+] Encontrados ${PINK}$ipfound${GREEN} IPs${RESET}"
	else
		echo -e "${YELLOW}[!] Nenhum IP descoberto (domínio pode estar protegido ou inacessível)${RESET}"
	fi

}

# +-+-+-+-+-+-+-+-+ +-+-+-+-+-+ +-+-+-+-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+
# |C|h|e|c|k|i|n|g| |w|h|i|c|h| |d|o|m|a|i|n|s| |a|r|e| |a|c|t|i|v|e|
# +-+-+-+-+-+-+-+-+ +-+-+-+-+-+ +-+-+-+-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+

checkActive() {
	local subdomains="$1"
	local output_folder="$2"

	if [ ! -f "$subdomains" ] || [ ! -s "$subdomains" ]; then
		echo -e "${YELLOW}[!] Nenhum subdomínio para testar${RESET}"
		return 0
	fi

	show_step_banner "6" "TESTANDO DOMÍNIOS - Verificando Ativos" "✅" "$GREEN"

	local domain_escaped=$(echo "$domain" | sed 's/\./\\./g')

	# Remove old .new file
	rm -f "$output_folder/alive.txt.new"

	if [ "$QUIET" != "True" ]; then
		# LIVE FEED MODE - Show each new domain as it's discovered
		echo -e "${CYAN}>>>${PURPLE} Running httprobe (live feed enabled)${RESET}"
		cat "$subdomains" | httprobe 2>/dev/null | \
		grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | \
		while read line; do
			echo -e "${GREEN}[NEW] $line${RESET}"
			echo "$line" >> "$output_folder/alive.txt.new"
		done

		echo -e "\n${CYAN}>>>${PURPLE} Running httpx (live feed enabled)${RESET}"
		cat "$subdomains" | httpx --silent --threads 300 2>/dev/null | \
		grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | \
		while read line; do
			echo -e "${GREEN}[NEW] $line${RESET}"
			echo "$line" >> "$output_folder/alive.txt.new"
		done
	else
		# QUIET MODE
		echo -e "${CYAN}[+] Active Domains 🔎${RESET}"
		cat "$subdomains" | httprobe 2>/dev/null | grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" >> "$output_folder/alive.txt.new"
		cat "$subdomains" | httpx --silent --threads 300 2>/dev/null | grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" >> "$output_folder/alive.txt.new"
	fi

	# Process results
	if [ -f "$output_folder/alive.txt.new" ] && [ -s "$output_folder/alive.txt.new" ]; then
		sort -u "$output_folder/alive.txt.new" -o "$output_folder/alive.txt.new"

		# ═══════════════════════════════════════════════════════════════════
		# 🚀  HTTP/HTTPS Deduplication
		# If HTTPS is alive, remove HTTP (same endpoint, prefer secure)
		# This saves time on WAF detection, screenshots, scanning, etc.
		# ═══════════════════════════════════════════════════════════════════
		local before_dedup=$(wc -l < "$output_folder/alive.txt.new")

		# Extract all HTTPS domains (without protocol)
		grep "^https://" "$output_folder/alive.txt.new" | sed 's|^https://||' | sort -u > "$output_folder/.https_domains.tmp"

		# Keep all HTTPS entries + HTTP entries that DON'T have HTTPS equivalent
		{
			# All HTTPS entries (always keep)
			grep "^https://" "$output_folder/alive.txt.new"
			# HTTP entries only if no HTTPS equivalent exists
			grep "^http://" "$output_folder/alive.txt.new" | while read http_url; do
				domain_part=$(echo "$http_url" | sed 's|^http://||')
				if ! grep -qxF "$domain_part" "$output_folder/.https_domains.tmp" 2>/dev/null; then
					echo "$http_url"
				fi
			done
		} | sort -u > "$output_folder/alive.txt.dedup"

		mv "$output_folder/alive.txt.dedup" "$output_folder/alive.txt.new"
		rm -f "$output_folder/.https_domains.tmp"

		local after_dedup=$(wc -l < "$output_folder/alive.txt.new")
		local removed=$((before_dedup - after_dedup))

		if [ "$removed" -gt 0 ]; then
			echo -e "${CYAN}[⚡] Removidos ${PINK}$removed${CYAN} HTTP duplicados (HTTPS preferido)${RESET}"
		fi

		# Merge with existing file
		if [ -f "$output_folder/alive.txt" ]; then
			local added=$(merge_results "$output_folder/alive.txt.new" "$output_folder/alive.txt")
			echo -e "${GREEN}[+] Adicionados ${PINK}$added${GREEN} novos domínios ativos${RESET}"
			NEW_TARGETS_FOUND=$((NEW_TARGETS_FOUND + added))
		else
			mv "$output_folder/alive.txt.new" "$output_folder/alive.txt"
		fi

		rm -f "$output_folder/alive.txt.new"
	fi

	# Count and display
	if [ -f "$output_folder/alive.txt" ] && [ -s "$output_folder/alive.txt" ]; then
		local total=$(cat "$output_folder/alive.txt" | wc -l)
		echo -e "${GREEN}[!] Total: ${PINK}$total${GREEN} domínios ativos${RESET}"

		# Timestamp tracking
		timestamp_and_track "$output_folder/alive.txt" "alive_domain"
	fi
}

# +-+-+-+ +-+-+-+-+-+-+-+-+-+
# |W|a|f| |D|e|t|e|c|t|i|o|n|
# +-+-+-+ +-+-+-+-+-+-+-+-+-+

wafDetect() {
	local alive_file="$1"
	local output_folder=$(dirname "$alive_file")

	if [ ! -f "$alive_file" ] || [ ! -s "$alive_file" ]; then
		echo -e "${YELLOW}[!] Nenhum domínio ativo para detectar WAF${RESET}"
		return 0
	fi

	show_step_banner "7" "DETECÇÃO WAF - Identificando Firewalls" "🛡️ " "$CYAN"

	# Incremental WAF detection
	local previous_checked="$output_folder/.waf_checked.txt"
	local new_domains_file="$output_folder/.new_waf_domains.txt"
	local waf_file="$output_folder/waf.txt"
	local waf_domains="$output_folder/alive-with-waf.txt"
	local nowaf_domains="$output_folder/alive-no-waf.txt"

	# Identify new domains
	if [ -f "$previous_checked" ]; then
		comm -13 <(sort "$previous_checked") <(sort "$alive_file") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | grep -v "^$" | wc -l)

		if [ "$new_count" -eq 0 ]; then
			echo -e "${CYAN}[SKIP] Nenhum domínio novo para detectar WAF${RESET}"
			# Still regenerate the lists from existing waf.txt
		else
			echo -e "${CYAN}[INCREMENTAL] Detectando WAF em ${PINK}$new_count${CYAN} novos domínios${RESET}"

			# BUGFIX: wafw00f -o saves CSV format, but we need the readable stdout
			# Capture stdout (readable format with "is behind") AND show to user
			if [ "$QUIET" == "True" ]; then
				wafw00f -i "$new_domains_file" -a 2>/dev/null >> "$output_folder/.waf.txt.new"
			else
				wafw00f -i "$new_domains_file" -a 2>/dev/null | tee -a "$output_folder/.waf.txt.new"
			fi

			# Merge results
			if [ -f "$output_folder/.waf.txt.new" ] && [ -s "$output_folder/.waf.txt.new" ]; then
				cat "$output_folder/.waf.txt.new" >> "$waf_file"
				rm "$output_folder/.waf.txt.new"
			fi

			# Update checked list
			cat "$new_domains_file" >> "$previous_checked"
			sort -u "$previous_checked" -o "$previous_checked"
			rm -f "$new_domains_file"
		fi
	else
		# First run - test all
		echo -e "${CYAN}[FULL-SCAN] Detectando WAF em todos os domínios ativos${RESET}"

		# BUGFIX: Capture stdout (readable format) instead of using -o flag
		if [ "$QUIET" == "True" ]; then
			wafw00f -i "$alive_file" -a 2>/dev/null > "$waf_file"
		else
			wafw00f -i "$alive_file" -a 2>/dev/null | tee "$waf_file"
		fi

		# Create checked list
		cp "$alive_file" "$previous_checked"
	fi

	echo -e ""
	echo -e "${PINK}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
	echo -e "${PINK}🛡️  SEPARANDO DOMÍNIOS COM/SEM WAF${RESET}"
	echo -e "${PINK}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

	# Parse wafw00f output to extract domains WITH WAF
	# wafw00f format: "https://domain.com is behind Cloudflare (Cloudflare Inc.)"
	# Also handles: "https://domain.com is behind Generic (Unknown)"
	if [ -f "$waf_file" ] && [ -s "$waf_file" ]; then
		# Extract URLs that have "is behind" (meaning WAF detected)
		grep -i "is behind" "$waf_file" 2>/dev/null | \
		grep -oE 'https?://[^ ]+' | \
		sed 's/[[:space:]]*$//' | \
		sort -u > "$waf_domains"

		# Also check for "appears to be behind" pattern
		grep -i "appears to be behind" "$waf_file" 2>/dev/null | \
		grep -oE 'https?://[^ ]+' | \
		sed 's/[[:space:]]*$//' | \
		sort -u >> "$waf_domains"

		# Deduplicate
		sort -u "$waf_domains" -o "$waf_domains" 2>/dev/null
	else
		# No WAF file, create empty waf_domains
		touch "$waf_domains"
	fi

	# Create list of domains WITHOUT WAF (safe to scan aggressively)
	# This is: alive.txt - alive-with-waf.txt
	if [ -f "$waf_domains" ] && [ -s "$waf_domains" ]; then
		comm -23 <(sort "$alive_file") <(sort "$waf_domains") > "$nowaf_domains"
	else
		# No WAF detected anywhere, all domains are safe
		cp "$alive_file" "$nowaf_domains"
	fi

	# Count and display results
	local waf_count=0
	local nowaf_count=0
	local total_count=$(cat "$alive_file" | wc -l)

	[ -f "$waf_domains" ] && waf_count=$(cat "$waf_domains" | wc -l)
	[ -f "$nowaf_domains" ] && nowaf_count=$(cat "$nowaf_domains" | wc -l)

	echo -e ""
	echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
	echo -e "${ORANGE}⚠️  RESULTADOS DA DETECÇÃO DE WAF${RESET}"
	echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
	echo -e ""
	echo -e "${GREEN}[+] Total de domínios ativos: ${PINK}$total_count${RESET}"
	echo -e "${ORANGE}[!] Domínios COM WAF (manual review): ${PINK}$waf_count${ORANGE} → ${YELLOW}$waf_domains${RESET}"
	echo -e "${GREEN}[+] Domínios SEM WAF (safe to scan): ${PINK}$nowaf_count${GREEN} → ${YELLOW}$nowaf_domains${RESET}"
	echo -e ""

	if [ "$waf_count" -gt 0 ]; then
		echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
		echo -e "${ORANGE}🚨 AVISO DE SEGURANÇA${RESET}"
		echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
		echo -e "${YELLOW}[!] Os ${PINK}$waf_count${YELLOW} domínios com WAF NÃO serão escaneados automaticamente${RESET}"
		echo -e "${YELLOW}[!] Isso previne que você seja bloqueado ou banido!${RESET}"
		echo -e "${YELLOW}[!] Revise manualmente: ${PINK}$waf_domains${RESET}"
		echo -e ""

		# Show which WAFs were detected
		if [ "$QUIET" != "True" ]; then
			echo -e "${CYAN}[*] WAFs detectados:${RESET}"
			grep -oE "is behind [^(]+" "$waf_file" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read count waf; do
				echo -e "    ${PURPLE}$count${CYAN} - $waf${RESET}"
			done
			echo -e ""
		fi
	fi

	echo -e "${GREEN}[✓] Próximos passos usarão apenas: ${PINK}alive-no-waf.txt${RESET}"
	echo -e "${GREEN}[!] WAF detection complete.${RESET}"
}

favAnalysis() {
	local alive_domains="$1"
	local output_folder="$2"
	local favout="$output_folder/favfreak"
	
	[ ! -f "$alive_domains" ] || [ ! -s "$alive_domains" ] && { echo -e "${YELLOW}[!] Nenhum domínio ativo para análise de favicon${RESET}"; return 0; }
	
	mkdir -p "$output_folder" "$favout" 2>/dev/null
	show_step_banner "8" "ANÁLISE FAVICON - Hash Fingerprinting" "🎨" "$PURPLE"
	
	# Incremental favicon analysis
	local previous_checked="$output_folder/.favicon_analyzed.txt"
	local new_domains_file="$output_folder/.new_fav_domains.txt"
	
	if [ -f "$previous_checked" ]; then
		comm -13 <(sort "$previous_checked") <(sort "$alive_domains") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)
		
		if [ "$new_count" -eq 0 ]; then
			echo -e "${CYAN}[SKIP] Nenhum domínio novo para análise de favicon${RESET}"
			return 0
		fi
		
		echo -e "${CYAN}[INCREMENTAL] Analisando ${PINK}$new_count${CYAN} novos domínios${RESET}"
		cat "$new_domains_file" | python3 "$SCRIPTPATH/tools/FavFreak/favfreak.py" --shodan -o "$favout" 2>/dev/null >/dev/null || true
		cat "$new_domains_file" >> "$previous_checked"
		sort -u "$previous_checked" -o "$previous_checked"
		rm "$new_domains_file"
	else
		if [ "$QUIET" == "True" ]; then
			cat "$alive_domains" | python3 "$SCRIPTPATH/tools/FavFreak/favfreak.py" --shodan -o "$favout" >/dev/null 2>&1
		else
			cat "$alive_domains" | python3 "$SCRIPTPATH/tools/FavFreak/favfreak.py" --shodan -o "$favout"
		fi
		cp "$alive_domains" "$previous_checked"
	fi
	
	echo -e "${CYAN}>>>${PURPLE} Hashes saved in ${PINK}$favout/${RESET}"
	local org="$(echo $domain | cut -d '.' -f1)"
	
	# Generate Shodan dorks
	for hash_file in "$favout"/*.txt; do
		[ -f "$hash_file" ] || continue
		local hash=$(basename "$hash_file" .txt | tr -d '/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\-')
		echo "org:\"$org\" http.favicon.hash:$hash" >> "$output_folder/shodan-manual.txt"
	done
}

dirFuzz() {
	local alive_domains="$1"
	local output_folder="$2"
	
	[ ! -f "$alive_domains" ] || [ ! -s "$alive_domains" ] && return 0
	
	show_step_banner "9" "DIRECTORY FUZZING - Brute Force" "📁" "$YELLOW"
	mkdir -p "$output_folder" 2>/dev/null
	
	for d in $(cat "$alive_domains"); do
		local dnohttps="$(echo $d | cut -d "/" -f3-)"
		echo -e "${GREEN}>>> Fuzzing $d${RESET}"
		ffuf -u "$d/FUZZ" -w "$wordlist" -t 100 -sf -s | tee "$output_folder/$dnohttps" || true
	done
}

credStuff() {
	local len="$1"
	local output_folder="$2"
	
	mkdir -p "$output_folder/credstuff" 2>/dev/null
	
	show_step_banner "10" "CREDENTIAL STUFFING - Hunting Leaks" "🔐" "$ORANGE"
	
	# Incremental credstuff
	local last_run="$output_folder/credstuff/.last_run_timestamp"
	local new_targets_file="$OUTFOLDER/.trackers/new_targets_last_24h.txt"
	
	if [ -f "$last_run" ] && [ -f "$new_targets_file" ]; then
		local new_count=$(cat "$new_targets_file" | wc -l)
		if [ "$new_count" -eq 0 ]; then
			echo -e "${CYAN}[SKIP] Nenhum novo alvo desde última execução${RESET}"
			return 0
		fi
		echo -e "${CYAN}[INCREMENTAL] CredStuff em ${PINK}$new_count${CYAN} novos alvos${RESET}"
	fi
	
	if [ "$QUIET" != "True" ]; then
		"$SCRIPTPATH/tools/CredStuff-Auxiliary/CredStuff_Auxiliary/main.sh" "$domain" "$len" | tee -a "$output_folder/credstuff/credstuff.txt"
	else
		"$SCRIPTPATH/tools/CredStuff-Auxiliary/CredStuff_Auxiliary/main.sh" "$domain" "$len" >> "$output_folder/credstuff/credstuff.txt" 2>/dev/null
	fi
	
	date +%s > "$last_run"
}

googleHacking() {
	local output_folder="$1"
	
	mkdir -p "$OUTFOLDER/dorks" "$output_folder" 2>/dev/null
	show_step_banner "11" "GOOGLE DORKS - Gerando Consultas" "🔍" "$CYAN"
	
	local dorks_file="$output_folder/dorks.txt"
	rm -f "$dorks_file"
	
	# 39 Google Dorks (keeping all from original)
	cat >> "$dorks_file" << EOF
site:$domain intitle:"Web user login"
site:$domain intitle:"login" "Are you a patient" "eRAD"
site:$domain inurl:wp-content/uploads/ intitle:"logs"
site:$domain intext:"password"
site:$domain filetype:sql ("values * MD5" | "values * password")
site:$domain "SQL Server Driver][SQL Server]Line 1: Incorrect syntax near"
site:$domain filetype:sql "insert into" (pass|passwd|password)
site:$domain intitle:"Apache2 Ubuntu Default Page: It works"
site:$domain intitle:index.of id_rsa -id_rsa.pub
site:$domain allinurl:*.php?txtCodiInfo=
site:$domain allinurl:auth_user_file.txt
site:$domain filetype:sql +"IDENTIFIED BY" -cvs
site:$domain allinurl:"/examples/jsp/snp/snoop.jsp"
site:$domain intext:"admin credentials"
site:$domain inurl:8080/login
site:$domain "Index of" inurl:phpmyadmin
site:$domain intitle:"index of" inurl:ftp
site:$domain allintext:username filetype:log
site:$domain "index of" "database.sql.zip"
site:$domain filetype:sql
site:$domain intext:Index of /
site:$domain intext:"database dump"
site:$domain filetype:log username putty
site:$domain filetype:xls inurl:"email.xls"
site:$domain intitle:"Index of" wp-admin
site:$domain allintitle:admin.php
site:$domain allinurl: admin mdb
site:$domain filetype:sql password
site:$domain filetype:STM STM
EOF
	
	echo -e "${GREEN}[!] 39 Google dorks gerados em ${PINK}$dorks_file${RESET}"
}

ghDork() {
	local output_folder="$1"
	
	mkdir -p "$OUTFOLDER/dorks" "$output_folder" 2>/dev/null
	show_step_banner "12" "GITHUB DORKS - Buscando Secrets" "💻" "$PURPLE"
	
	for subdomain in $(cat "$DOMAINS" 2>/dev/null | head -50); do
		local outfile="$output_folder/$subdomain.txt"
		local without_suffix=$(echo "$subdomain" | cut -d . -f1)
		
		cat > "$outfile" << EOF
$subdomain
************ Github Dork Links (must be logged in) *******************
https://github.com/search?q="$subdomain"+password&type=Code
https://github.com/search?q="$subdomain"+api_key&type=Code
https://github.com/search?q="$subdomain"+SECRET_KEY&type=Code
https://github.com/search?q="$subdomain"+aws_access_key_id&type=Code
https://github.com/search?q="$subdomain"+.env&type=Code
https://github.com/search?q="$subdomain"+credentials&type=Code
EOF
	done
	
	echo -e "${GREEN}[!] GitHub dorks saved in ${PINK}$output_folder/*.txt${RESET}"
}

screenshots() {
	local alive_domains="$1"
	local output_folder="$2"
	
	[ ! -f "$alive_domains" ] || [ ! -s "$alive_domains" ] && return 0
	
	show_step_banner "13" "SCREENSHOTS - Capturando Páginas" "📸" "$CYAN"
	
	# Incremental screenshots
	local previous_checked="$output_folder/.screenshot_captured.txt"
	local new_domains_file="$output_folder/.new_screenshot_domains.txt"
	
	if [ -f "$previous_checked" ]; then
		comm -13 <(sort "$previous_checked") <(sort "$alive_domains") > "$new_domains_file"
		local new_count=$(cat "$new_domains_file" | wc -l)
		
		if [ "$new_count" -eq 0 ]; then
			echo -e "${CYAN}[SKIP] Nenhum domínio novo para screenshot${RESET}"
			return 0
		fi
		
		echo -e "${CYAN}[INCREMENTAL] Capturando ${PINK}$new_count${CYAN} novos screenshots${RESET}"
		python3 "$SCRIPTPATH/tools/EyeWitness/Python/EyeWitness.py" --web --no-prompt -f "$new_domains_file" -d "$output_folder" --user-agent "Mozilla/5.0" 2>&1 | grep -v "WebDriver" | grep -v "Stacktrace" || true
		cat "$new_domains_file" >> "$previous_checked"
		sort -u "$previous_checked" -o "$previous_checked"
		rm "$new_domains_file"
	else
		python3 "$SCRIPTPATH/tools/EyeWitness/Python/EyeWitness.py" --web --no-prompt -f "$alive_domains" -d "$output_folder" --user-agent "Mozilla/5.0" 2>&1 | grep -v "WebDriver" | grep -v "Stacktrace" || true
		cp "$alive_domains" "$previous_checked"
	fi
}

portscan() {
	local domains="$1"
	local ips="$2"
	local output_folder="$3"
	
	mkdir -p "$output_folder" 2>/dev/null
	
	show_step_banner "14" "PORT SCAN - Mapeando Serviços" "🔌" "$ORANGE"
	
	if [ "$QUIET" != "True" ]; then
		nmap -iL "$domains" --top-ports 5000 --max-rate=50000 -oG "$output_folder/nmap.txt" 2>/dev/null || true
		sudo masscan -p1-65535 -iL "$ips" --max-rate=50000 -oG "$output_folder/masscan.txt" 2>/dev/null || true
		cat "$domains" | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe >> "$output_folder/naabu.txt" || true
	else
		nmap -iL "$domains" --top-ports 5000 --max-rate=50000 -oG "$output_folder/nmap.txt" >/dev/null 2>&1 || true
		sudo masscan -p1-65535 -iL "$ips" --max-rate=50000 -oG "$output_folder/masscan.txt" >/dev/null 2>&1 || true
		cat "$domains" | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe >> "$output_folder/naabu.txt" 2>/dev/null || true
	fi
}

linkDiscovery() {
	local alive_domains="$1"
	local output_folder="$2"

	[ ! -f "$alive_domains" ] || [ ! -s "$alive_domains" ] && return 0

	mkdir -p "$output_folder" 2>/dev/null
	show_step_banner "15" "DESCOBERTA DE LINKS - Crawling URLs" "🔗" "$CYAN"

	local domain_escaped=$(echo "$domain" | sed 's/\./\\./g')
	local total_domains=$(wc -l < "$alive_domains")
	local counter=0
	local temp_all="$output_folder/.all_temp.txt"
	> "$temp_all"  # Clear temp file

	echo -e "${CYAN}[*] Total de alvos: ${PINK}$total_domains${RESET}"
	echo -e ""

	# ═══════════════════════════════════════════════════════════════════
	# 🚀  Fast URL discovery with multiple tools in parallel
	# ═══════════════════════════════════════════════════════════════════

	# 1. KATANA - Fast modern crawler (10x faster than hakrawler)
	echo -e "${ORANGE}>>> [1/4] Katana (fast crawler)...${RESET}"
	if command -v katana &>/dev/null; then
		# Use stdin for input, simpler and more reliable
		cat "$alive_domains" | katana -d 2 -jc -kf -silent -nc 2>/dev/null | \
		grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | \
		tee -a "$temp_all" | \
		while read -r url; do
			echo -e "${GREEN}[KATANA] $url${RESET}"
		done
	else
		echo -e "${YELLOW}[!] katana não instalado, pulando...${RESET}"
	fi

	# 2. WAYBACKURLS - Historical URLs (batch mode = faster)
	echo -e "${ORANGE}>>> [2/4] Waybackurls (historical)...${RESET}"
	cat "$alive_domains" | sed 's|https\?://||g' | cut -d'/' -f1 | sort -u | \
	waybackurls 2>/dev/null | \
	grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | \
	tee -a "$temp_all" | \
	while read -r url; do
		echo -e "${CYAN}[WAYBACK] $url${RESET}"
	done

	# 3. GAU - GetAllUrls (OTX, Wayback, Common Crawl)
	echo -e "${ORANGE}>>> [3/4] GAU (multiple sources)...${RESET}"
	if command -v gau &>/dev/null; then
		cat "$alive_domains" | sed 's|https\?://||g' | cut -d'/' -f1 | sort -u | \
		gau --threads 5 --subs 2>/dev/null | \
		grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | \
		tee -a "$temp_all" | \
		while read -r url; do
			echo -e "${PURPLE}[GAU] $url${RESET}"
		done
	else
		echo -e "${YELLOW}[!] gau não instalado, pulando...${RESET}"
	fi

	# 4. HAKRAWLER - Fallback crawling (fast mode)
	echo -e "${ORANGE}>>> [4/4] Hakrawler (crawling)...${RESET}"
	cat "$alive_domains" | hakrawler -t 20 -timeout 10 2>/dev/null | \
	grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" | \
	tee -a "$temp_all" | \
	while read -r url; do
		echo -e "${PINK}[HAKRAWL] $url${RESET}"
	done

	# ═══════════════════════════════════════════════════════════════════
	# Aggregate and deduplicate
	# ═══════════════════════════════════════════════════════════════════

	echo -e ""
	echo -e "${CYAN}[*] Agregando e deduplicando resultados...${RESET}"

	# Merge with existing if re-scan
	if [ -f "$output_folder/all.txt" ]; then
		cat "$output_folder/all.txt" >> "$temp_all"
	fi

	# Basic deduplication
	sort -u "$temp_all" > "$output_folder/all.txt"
	rm -f "$temp_all"

	local before_param_dedup=$(wc -l < "$output_folder/all.txt")

	# ═══════════════════════════════════════════════════════════════════
	# 🚀 FAST Parameter-based URL deduplication (handles 200k+ URLs fast)
	# URLs with same path+params but different values = same endpoint
	# ═══════════════════════════════════════════════════════════════════

	# Skip if less than 1000 URLs (not worth the overhead)
	if [ "$before_param_dedup" -lt 1000 ]; then
		echo -e "${GREEN}[✓] Total de endpoints únicos: ${PINK}$before_param_dedup${RESET}"
		timestamp_and_track "$output_folder/all.txt" "url"
		return
	fi

	echo -e "${CYAN}[*] Deduplicando ${PINK}$before_param_dedup${CYAN} URLs por parâmetros...${RESET}"

	# FAST METHOD: Use sed to normalize param values, then sort -u
	# Step 1: Create normalized version (param=VALUE -> param=)
	# Step 2: Paste original + normalized side by side
	# Step 3: Sort by normalized, keep first occurrence
	# Step 4: Extract original URL

	# This is O(n log n) instead of O(n²) - handles 200k URLs in seconds!
	{
		paste -d$'\t' \
			<(sed 's/=[^&]*\([&]\)/=\1/g; s/=[^&]*$/=/' "$output_folder/all.txt") \
			"$output_folder/all.txt"
	} | sort -t$'\t' -k1,1 -u | cut -f2 > "$output_folder/all.txt.dedup"

	mv "$output_folder/all.txt.dedup" "$output_folder/all.txt"

	local after_param_dedup=$(wc -l < "$output_folder/all.txt")
	local param_removed=$((before_param_dedup - after_param_dedup))

	if [ "$param_removed" -gt 0 ]; then
		echo -e "${CYAN}[⚡] Removidas ${PINK}$param_removed${CYAN} URLs duplicadas${RESET}"
	fi

	echo -e "${GREEN}[✓] Total de endpoints únicos: ${PINK}$after_param_dedup${RESET}"

	timestamp_and_track "$output_folder/all.txt" "url"
}

endpointsEnumeration() {
	local alive_domains="$1"
	local output_folder="$2"
	
	[ ! -f "$alive_domains" ] || [ ! -s "$alive_domains" ] && return 0
	
	show_step_banner "16" "ENUMERAÇÃO DE ENDPOINTS - Caça a Parâmetros" "📡" "$PURPLE"
	
	local domain_escaped=$(echo "$domain" | sed 's/\./\\./g')
	mkdir -p "$output_folder/js" 2>/dev/null
	
	# ParamSpider in stream mode (fix for path issue)
	while read -r d; do
		echo -e "${CYAN}>>> ParamSpider on $d${RESET}"
		python3 "$SCRIPTPATH/tools/ParamSpider/paramspider.py" -d "$d" -s 2>/dev/null | grep -E "https?://([^/]*\.)?${domain_escaped}(/|:|$)" >> "$output_folder/all.txt" || true
	done < "$alive_domains"
	
	# JS enumeration
	xargs -P 20 -a "$DOMAINS" -I@ bash -c "
		nc -w1 -z -v @ 443 2>/dev/null && echo @ | xargs -I{} bash -c '
			gospider -a -s \"https://{}\" -d 2 2>/dev/null | grep -Eo \"(http|https)://[^/\\\"]*\.js+\" | grep -E \"${domain_escaped}\"
		'
	" >> "$output_folder/js/js.txt" 2>/dev/null || true
	
	cat "$alive_domains" | waybackurls 2>/dev/null | grep -iE '\.js' | grep -iEv '(\.jsp|\.json)' | grep -E "$domain_escaped" >> "$output_folder/js/js.txt" || true
	sort -u "$output_folder/js/js.txt" -o "$output_folder/js/js.txt" 2>/dev/null
	
	cat "$output_folder/js/js.txt" | anti-burl | awk '{print $4}' | sort -u >> "$output_folder/js/AliveJS.txt" 2>/dev/null || true
}

findVuln() {
	local alive_domains="$1"
	local output_folder="$2"

	[ ! -f "$alive_domains" ] || [ ! -s "$alive_domains" ] && return 0

	mkdir -p "$output_folder" "$output_folder/xss-discovery" 2>/dev/null
	show_step_banner "17" "SCAN DE VULNERABILIDADES - Hunting Bugs" "🔥" "$ORANGE"

	# ═══════════════════════════════════════════════════════════════════
	# 🔥 REAL-TIME VULNERABILITY SCANNING 
	# Every second counts in bug bounty! Show findings AS THEY HAPPEN!
	# ═══════════════════════════════════════════════════════════════════

	local tested_targets="$output_folder/.tested_targets.txt"
	local in_progress_file="$output_folder/.scan_in_progress.txt"
	local NUCLEI_RATE_LIMIT=150

	# Update templates silently in background
	nuclei --update-templates >/dev/null 2>&1 &

	echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
	echo -e "${ORANGE}🔥 REAL-TIME VULNERABILITY HUNTING${RESET}"
	echo -e "${CYAN}   👀 Resultados aparecem INSTANTANEAMENTE${RESET}"
	echo -e "${CYAN}   ⚡ Viu um bug? REPORTA AGORA enquanto scan continua!${RESET}"
	echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
	echo -e ""
	echo -e "${CYAN}[*] Rate limit: ${PINK}$NUCLEI_RATE_LIMIT${CYAN} req/sec | Output: ${PINK}REAL-TIME${RESET}"
	echo -e ""

	# ═══════════════════════════════════════════════════════════════════
	# SMART TRACKING: Check what was ACTUALLY tested vs just listed
	# ═══════════════════════════════════════════════════════════════════

	# Get all targets to test
	local all_targets=$(cat "$alive_domains" | sort -u)
	# grep -v "^$" to avoid counting empty lines (echo "" | wc -l returns 1)
	local total_count=$(echo "$all_targets" | grep -v "^$" | wc -l)

	# Check what was actually completed (not just started)
	local completed_file="$output_folder/.completed_targets.txt"
	touch "$completed_file" 2>/dev/null

	# Find targets that haven't been COMPLETED yet
	# comm requires BOTH inputs to be sorted - re-sort to guarantee consistency
	local pending_targets=$(comm -23 <(echo "$all_targets" | sort) <(sort "$completed_file" 2>/dev/null))
	local pending_count=$(echo "$pending_targets" | grep -v "^$" | wc -l)

	if [ "$pending_count" -eq 0 ]; then
		echo -e "${GREEN}[✓] Todos os ${PINK}$total_count${GREEN} alvos já foram escaneados anteriormente!${RESET}"
		echo -e "${YELLOW}[TIP] Para forçar re-scan, delete: ${PINK}$completed_file${RESET}"
		echo -e ""
	else
		echo -e "${CYAN}[*] Total de alvos: ${PINK}$total_count${RESET}"
		echo -e "${CYAN}[*] Já escaneados: ${PINK}$((total_count - pending_count))${RESET}"
		echo -e "${GREEN}[*] Pendentes: ${PINK}$pending_count${GREEN} (serão escaneados agora)${RESET}"
		echo -e ""

		# Save pending targets to temp file
		echo "$pending_targets" | grep -v "^$" > "$output_folder/.pending_targets.txt"


		echo -e "${ORANGE}════════════════════════════════════════════════════════════${RESET}"
		echo -e "${ORANGE}  🔥 NUCLEI SCAN INICIANDO - RESULTADOS EM TEMPO REAL 🔥    ${RESET}"
		echo -e "${ORANGE}════════════════════════════════════════════════════════════${RESET}"
		echo -e ""

		nuclei -l "$output_folder/.pending_targets.txt" \
			-t "$HOME/nuclei-templates/" \
			-rl "$NUCLEI_RATE_LIMIT" \
			-c 50 \
			-stats \
			-si 30 \
			-o "$output_folder/nuclei_findings.txt" \
			2>&1 | while IFS= read -r line; do
				# Colorize severity levels for instant visual feedback
				if echo "$line" | grep -qE "\[critical\]"; then
					echo -e "${ORANGE}🚨🚨🚨 CRITICAL 🚨🚨🚨${RESET}"
					echo -e "${ORANGE}$line${RESET}"
					echo -e "${ORANGE}👆 REPORTA ISSO AGORA! 👆${RESET}"
					echo ""
				elif echo "$line" | grep -qE "\[high\]"; then
					echo -e "${PINK}🔥 HIGH: $line${RESET}"
				elif echo "$line" | grep -qE "\[medium\]"; then
					echo -e "${YELLOW}⚠️  MEDIUM: $line${RESET}"
				elif echo "$line" | grep -qE "\[low\]"; then
					echo -e "${CYAN}ℹ️  LOW: $line${RESET}"
				elif echo "$line" | grep -qE "\[info\]"; then
					echo -e "${PURPLE}📋 INFO: $line${RESET}"
				elif echo "$line" | grep -qE "^\[INF\]|^\[WRN\]|Templates:|Targets:|^$"; then
					# Stats and info lines - show but dimmer
					echo -e "${CYAN}$line${RESET}"
				else
					echo "$line"
				fi
			done

		# Mark all pending as completed AFTER scan finishes
		cat "$output_folder/.pending_targets.txt" >> "$completed_file"
		sort -u "$completed_file" -o "$completed_file"

		# Cleanup
		rm -f "$output_folder/.pending_targets.txt"

		echo -e ""
		echo -e "${GREEN}════════════════════════════════════════════════════════════${RESET}"
		echo -e "${GREEN}  ✅ NUCLEI SCAN COMPLETO!                                   ${RESET}"
		echo -e "${GREEN}════════════════════════════════════════════════════════════${RESET}"

		# Show summary of findings
		if [ -f "$output_folder/nuclei_findings.txt" ] && [ -s "$output_folder/nuclei_findings.txt" ]; then
			local critical_count=$(grep -c "\[critical\]" "$output_folder/nuclei_findings.txt" 2>/dev/null || echo "0")
			local high_count=$(grep -c "\[high\]" "$output_folder/nuclei_findings.txt" 2>/dev/null || echo "0")
			local medium_count=$(grep -c "\[medium\]" "$output_folder/nuclei_findings.txt" 2>/dev/null || echo "0")
			local low_count=$(grep -c "\[low\]" "$output_folder/nuclei_findings.txt" 2>/dev/null || echo "0")

			echo -e ""
			echo -e "${ORANGE}[!] CRITICAL: ${PINK}$critical_count${RESET}"
			echo -e "${PINK}[!] HIGH: ${PINK}$high_count${RESET}"
			echo -e "${YELLOW}[!] MEDIUM: ${PINK}$medium_count${RESET}"
			echo -e "${CYAN}[!] LOW: ${PINK}$low_count${RESET}"

			if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
				echo -e ""
				echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
				echo -e "${ORANGE}🚨 BUGS DE ALTA SEVERIDADE ENCONTRADOS!${RESET}"
				echo -e "${ORANGE}👆 FAÇA O REPORT IMEDIATAMENTE!${RESET}"
				echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
			fi
		fi
	fi

	# ═══════════════════════════════════════════════════════════════════
	# XSS, LFI, SQLi, RCE, Open Redirect detection
	# ═══════════════════════════════════════════════════════════════════

	echo -e ""
	echo -e "${CYAN}[*] Buscando padrões de vulnerabilidades em URLs...${RESET}"

	local list="$OUTFOLDER/link-discovery/all.txt"

	if [ -f "$list" ] && [ -s "$list" ]; then
		# Gxss with real-time output
		echo -e "${CYAN}>>> Scanning for XSS...${RESET}"
		cat "$list" | anti-burl 2>/dev/null | awk '{print $4}' | grep -E "^https?://" | \
		Gxss -p XSS 2>/dev/null | sed '/^$/d' | tee "$output_folder/xss-discovery/possible-xss.txt" | \
		while read -r xss_line; do
			[ -n "$xss_line" ] && echo -e "${PINK}[XSS] $xss_line${RESET}"
		done

		# Pattern matching for vulnerabilities
		echo -e "${CYAN}>>> Checking Open Redirect patterns...${RESET}"
		grepVuln open_redir_parameters[@] "$(cat $list)" "$output_folder/possible-open-redir.txt"

		echo -e "${CYAN}>>> Checking RCE patterns...${RESET}"
		grepVuln rce_parameters[@] "$(cat $list)" "$output_folder/rce.txt"

		echo -e "${CYAN}>>> Checking LFI patterns...${RESET}"
		grepVuln lfi_parameters[@] "$(cat $list)" "$output_folder/lfi.txt"

		# gf patterns if available
		if command -v gf &>/dev/null; then
			echo -e "${CYAN}>>> Running gf patterns...${RESET}"
			cat "$list" 2>/dev/null | gf lfi >> "$output_folder/lfi.txt" 2>/dev/null || true
			cat "$DOMAINS" 2>/dev/null | waybackurls 2>/dev/null | gf sqli >> "$output_folder/possible-sqli.txt" 2>/dev/null || true
		fi
	fi
	
	echo -e "${GREEN}[!] Vulnerability scan complete!${RESET}"
}

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |M|A|I|N| |E|X|E|C|U|T|I|O|N| |P|I|P|E|L|I|N|E|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Show help if requested
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	printBanner
	show_help
	exit 0
fi

# Parse command-line arguments
while getopts ":d:w:t:g:s:q:o:f:Q" ops; do
	case "${ops}" in
		d) domain=${OPTARG} ;;
		w) wordlist=${OPTARG} ;;
		g) GHAPIKEY=${OPTARG} ;;
		s) SHODANAPIKEY=${OPTARG} ;;
		q) QUIET="True" ;;
		o) OUTFOLDER=${OPTARG} ;;
		f) FUZZ="True" ;;
		Q) QUICK_MODE="True" ;;
		:)
			if [ "${OPTARG}" == "q" ]; then
				QUIET="True"
			elif [ "${OPTARG}" == "f" ]; then
				FUZZ="True"
			elif [ "${OPTARG}" == "Q" ]; then
				QUICK_MODE="True"
			else
				echo -e "${ORANGE}[-] Error: -${OPTARG} requires an argument!${RESET}"
				exit 1
			fi
			;;
		\?)
			echo -e "${ORANGE}[-] Error: -${OPTARG} is an Invalid Option${RESET}"
			exit 1
			;;
	esac
done

# Set defaults
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
[ -z "$OUTFOLDER" ] && OUTFOLDER="$SCRIPTPATH/$domain"
DOMAINS="$OUTFOLDER/subdomains/subdomains.txt"
[ -z "$GHAPIKEY" ] && GHAPIKEY="False"
[ -z "$SHODANAPIKEY" ] && SHODANAPIKEY="False"

# Validate required arguments
if [ -z "$domain" ]; then
	echo -e "${ORANGE}[-] Unspecified domain! ❌${RESET}"
	show_help
	exit 1
fi

if [ -z "$wordlist" ]; then
	echo -e "${YELLOW}[!] You didn't choose a wordlist. Available options:${RESET}"
	for wl in "$SCRIPTPATH/wordlists"/*; do
		echo -e "${GREEN}[+] $wl${RESET}"
	done
	exit 1
fi

# Check dependencies (basic check)
printBanner

echo -e "${CYAN}[!] Checking dependencies...${RESET}"
dep_missing=0

# Check critical tools
for tool in assetfinder subfinder amass httprobe httpx nuclei dnsx subjack wafw00f; do
	if ! command -v "$tool" &>/dev/null && ! command -v "$GOPATH/bin/$tool" &>/dev/null; then
		echo -e "${ORANGE}[-] Missing: $tool${RESET}"
		dep_missing=1
	fi
done

# Check Python tools
if ! command -v python3 &>/dev/null; then
	echo -e "${ORANGE}[-] Missing: python3${RESET}"
	dep_missing=1
fi

# Check tools directory
if [ ! -d "$SCRIPTPATH/tools" ]; then
	echo -e "${ORANGE}[-] tools/ directory not found. Run installation.sh${RESET}"
	dep_missing=1
fi

if [ "$dep_missing" -eq 1 ]; then
	echo -e "${ORANGE}[-] Missing dependencies! Run ./installation.sh${RESET}"
	exit 1
else
	echo -e "${GREEN}[+] All dependencies OK! ✅${RESET}"
fi

# Create output folder
mkdir -p "$OUTFOLDER" 2>/dev/null

# Initialize checkpoint system
init_checkpoint

# Check for recent scans (suggest quick mode)
check_recent_scan

# Show initial progress
show_progress

# ═════════════════════════════════════════════════════════════
#                  EXECUTE PIPELINE WITH CHECKPOINTS
# ═════════════════════════════════════════════════════════════

# Phase 1: Discovery
run_step "asn_enum" asnEnum "$domain" "$OUTFOLDER/asn"
run_step "subdomain_enum" subdomainEnumeration "$domain" "$OUTFOLDER/subdomains"
run_step "organize_domains" organizeDomains "$DOMAINS" "$OUTFOLDER/subdomains"
run_step "subdomain_takeover" subdomainTakeover "$DOMAINS" "$OUTFOLDER/subdomains/subdomain-takeover"
run_step "dns_lookup" dnsLookup "$DOMAINS" "$OUTFOLDER"
run_step "check_active" checkActive "$DOMAINS" "$OUTFOLDER/subdomains"

# Phase 2: Reconnaissance & WAF Detection
run_step "waf_detect" wafDetect "$OUTFOLDER/subdomains/alive.txt"
run_step "favicon_analysis" favAnalysis "$OUTFOLDER/subdomains/alive.txt" "$OUTFOLDER/favicon-analysis"

# ═══════════════════════════════════════════════════════════════════
# 🛡️ WAF-AWARE SCANNING - Use alive-no-waf.txt for aggressive scans!
# This prevents getting blocked by WAFs like Cloudflare, Akamai, etc.
# Domains WITH WAF are saved in alive-with-waf.txt for manual review.
# ═══════════════════════════════════════════════════════════════════

# Define the safe target list (domains WITHOUT WAF protection)
SAFE_TARGETS="$OUTFOLDER/subdomains/alive-no-waf.txt"

# Fallback to alive.txt if alive-no-waf.txt doesn't exist yet
if [ ! -f "$SAFE_TARGETS" ]; then
	SAFE_TARGETS="$OUTFOLDER/subdomains/alive.txt"
fi

# Phase 3: Intelligence Gathering
run_step "cred_stuff" credStuff 500 "$OUTFOLDER/dorks"
run_step "google_hacking" googleHacking "$OUTFOLDER/dorks/google-dorks"
run_step "github_dorks" ghDork "$OUTFOLDER/dorks/github-dorks"
run_step "screenshots" screenshots "$SAFE_TARGETS" "$OUTFOLDER/$domain-screenshots"

# Phase 4: Active Scanning (optional - comment out if not needed)
# run_step "port_scanning" portscan "$DOMAINS" "$OUTFOLDER/DNS/ip_only.txt" "$OUTFOLDER/portscan"

# Phase 5: URL Discovery (uses safe targets to avoid WAF blocks)
run_step "link_discovery" linkDiscovery "$SAFE_TARGETS" "$OUTFOLDER/link-discovery"
run_step "endpoints_enum" endpointsEnumeration "$SAFE_TARGETS" "$OUTFOLDER/link-discovery"

# Phase 6: Vulnerability Scanning (ONLY on non-WAF domains!)
run_step "vulnerability_scan" findVuln "$SAFE_TARGETS" "$OUTFOLDER/vuln"

# ═════════════════════════════════════════════════════════════
#                      FINAL SUMMARY REPORT
# ═════════════════════════════════════════════════════════════

echo -e "\n${PINK}════════════════════════════════════════════════════════════${RESET}"
echo -e "${PINK}                   FINAL RESULTS - CVE-HUNTERS              ${RESET}"
echo -e "${PINK}════════════════════════════════════════════════════════════${RESET}\n"

# Count results (NOT using 'local' - we're in main script body, not inside a function)
org="$(echo $domain | cut -d '.' -f1)"
asn_count=0
sub_count=0
alive_count=0
waf_count=0
nowaf_count=0
takeover_count=0
ip_count=0
fav_count=0
link_count=0
js_count=0
vuln_count=0

[ -f "$OUTFOLDER/asn/$org.txt" ] && asn_count=$(cat "$OUTFOLDER/asn/$org.txt" | wc -l)
[ -f "$DOMAINS" ] && sub_count=$(cat "$DOMAINS" | wc -l)
[ -f "$OUTFOLDER/subdomains/alive.txt" ] && alive_count=$(cat "$OUTFOLDER/subdomains/alive.txt" | wc -l)
[ -f "$OUTFOLDER/subdomains/alive-with-waf.txt" ] && waf_count=$(cat "$OUTFOLDER/subdomains/alive-with-waf.txt" | wc -l)
[ -f "$OUTFOLDER/subdomains/alive-no-waf.txt" ] && nowaf_count=$(cat "$OUTFOLDER/subdomains/alive-no-waf.txt" | wc -l)
[ -f "$OUTFOLDER/subdomains/subdomain-takeover/takeover.txt" ] && takeover_count=$(cat "$OUTFOLDER/subdomains/subdomain-takeover/takeover.txt" | wc -l)
[ -f "$OUTFOLDER/DNS/ip_only.txt" ] && ip_count=$(cat "$OUTFOLDER/DNS/ip_only.txt" | wc -l)
[ -d "$OUTFOLDER/favicon-analysis/favfreak" ] && fav_count=$(ls "$OUTFOLDER/favicon-analysis/favfreak"/*.txt 2>/dev/null | wc -l)
[ -f "$OUTFOLDER/link-discovery/all.txt" ] && link_count=$(cat "$OUTFOLDER/link-discovery/all.txt" | wc -l)
[ -f "$OUTFOLDER/link-discovery/js/js.txt" ] && js_count=$(cat "$OUTFOLDER/link-discovery/js/js.txt" | wc -l)

# Count vulnerabilities
if [ -d "$OUTFOLDER/vuln" ]; then
	vuln_count=$(($(cat "$OUTFOLDER/vuln"/*.txt 2>/dev/null | wc -l) + $(cat "$OUTFOLDER/vuln/xss-discovery"/*.txt 2>/dev/null | wc -l)))
fi

# Display summary
echo -e "${GREEN}[+] ASNs Found: ${PINK}$asn_count${RESET}"
echo -e "${GREEN}[+] Subdomains Found: ${PINK}$sub_count${RESET}"
echo -e "${GREEN}[+] Subdomains Alive: ${PINK}$alive_count${RESET}"

# WAF Status (Critical Security Info)
echo -e ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${CYAN}🛡️  WAF STATUS${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}[+] Domains WITHOUT WAF (scanned): ${PINK}$nowaf_count${RESET}"
if [ "$waf_count" -gt 0 ]; then
	echo -e "${ORANGE}[!] Domains WITH WAF (skipped): ${PINK}$waf_count${ORANGE} → ${YELLOW}alive-with-waf.txt${RESET}"
else
	echo -e "${GREEN}[+] Domains WITH WAF: ${PINK}0${GREEN} (none detected)${RESET}"
fi
echo -e ""

if [ "$takeover_count" -gt 0 ]; then
	echo -e "${ORANGE}[!] Subdomain Takeovers: ${PINK}$takeover_count${ORANGE} ⚠️ ${RESET}"
else
	echo -e "${GREEN}[+] Subdomain Takeovers: ${PINK}0${RESET}"
fi

echo -e "${GREEN}[+] IPs Found: ${PINK}$ip_count${RESET}"
[ -f "$OUTFOLDER/DNS/dnsrecon.txt" ] && echo -e "${GREEN}[+] DNS Enumeration: ✅${RESET}"
echo -e "${GREEN}[+] Favicon Hashes: ${PINK}$fav_count${RESET}"
echo -e "${GREEN}[+] Links Found: ${PINK}$link_count${RESET}"
echo -e "${GREEN}[+] JS Files Found: ${PINK}$js_count${RESET}"

if [ "$vuln_count" -gt 0 ]; then
	echo -e "${ORANGE}[!] Possible Vulnerabilities: ${PINK}$vuln_count${ORANGE} 🔥${RESET}"
else
	echo -e "${GREEN}[+] Vulnerabilities Scanned: ✅${RESET}"
fi

# Show new targets found
if [ "$NEW_TARGETS_FOUND" -gt 0 ]; then
	echo -e "\n${CYAN}[+] New Targets Discovered This Run: ${PINK}$NEW_TARGETS_FOUND${RESET}"
fi

# Show trackers info
if [ -f "$OUTFOLDER/.trackers/new_targets_last_24h.txt" ]; then
	# BUG FIX: 'local' keyword is only valid inside functions - removed
	new_24h=$(cat "$OUTFOLDER/.trackers/new_targets_last_24h.txt" | grep -v "^$" | wc -l)
	if [ "$new_24h" -gt 0 ]; then
		echo -e "${YELLOW}[!] Targets discovered in last 24h: ${PINK}$new_24h${YELLOW} (high priority for testing!)${RESET}"
	fi
fi

echo -e "\n${GREEN}[+] All results saved in: ${PINK}$OUTFOLDER${RESET}"
echo -e "${YELLOW}[!] Check dorks manually for best results!${RESET}"
echo -e "\n${PINK}════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}                        SCAN COMPLETE! 😁                    ${RESET}"
echo -e "${PINK}════════════════════════════════════════════════════════════${RESET}\n"

# Done!
exit 0
