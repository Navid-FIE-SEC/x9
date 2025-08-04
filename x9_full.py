#!/usr/bin/env python3
import subprocess
import sys
import os
import tempfile
from argparse import ArgumentParser, RawTextHelpFormatter
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
import math
import concurrent.futures
import json
from datetime import datetime

class colors:
    GRAY = "\033[90m"
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    NOCOLOR = RESET

def print_colored(msg, color=colors.GREEN):
    global_args = getattr(sys.modules['__main__'], 'args', None)
    if global_args is None or not getattr(global_args, 'silent', False):
        print(f"{color}{msg}{colors.RESET}")

def run_command_in_bash(command, capture_output=True, check=True):
    print_colored(f"[*] Executing: {command}", colors.YELLOW)
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=capture_output,
            text=True,
            check=check,
            encoding='utf-8',
            errors='replace'
        )
        if result.stderr:
            print_colored(f"Warning/Error from command: {result.stderr.strip()}", colors.YELLOW)
        
        if capture_output:
            return result.stdout.strip()
        else:
            if result.returncode != 0:
                print_colored(f"ERROR: Command exited with non-zero status: '{command}' (Exit Code: {result.returncode})", colors.RED)
                return None
            return ""
    except subprocess.CalledProcessError as exc:
        print_colored(f"ERROR: Command failed: '{command}'\nExit Code: {exc.returncode}\nStderr: {exc.stderr.strip()}", colors.RED)
        return None
    except FileNotFoundError:
        print_colored(f"ERROR: Command not found in PATH: '{command.split()[0]}'", colors.RED)
        return None
    except Exception as e:
        print_colored(f"ERROR: An unexpected error occurred while running command '{command}': {e}", colors.RED)
        return None

def is_url_fuzzable(url):
    static_extensions = {
        '.json', '.js', '.fnt', '.ogg', '.css', '.jpg', '.png', '.svg', '.img', '.gif',
        '.exe', '.mp4', '.flv', '.pdf', '.doc', '.ogv', '.webm', '.wmv', '.webp', '.mov',
        '.mp3', '.m4a', '.m4p', '.ppt', '.pptx', '.sccs', '.tif', '.tiff', '.ttf', '.otf',
        '.woff', '.woff2', '.bmp', '.ico', '.eot', '.htc', '.swf', '.rtf', '.image', '.rf',
        '.txt', '.xml', '.zip', '.rar', '.7z', '.tar', '.gz'
    }
    try:
        parsed_url = urlparse(url)
        if not parsed_url.query and '%3F' not in url.lower():
            return False
        if any(parsed_url.path.lower().endswith(ext) for ext in static_extensions):
            return False
        return True
    except Exception as e:
        print_colored(f"Warning: Error during URL fuzzability check for {url}: {str(e)}", colors.YELLOW)
        return False

def gather_urls_passively(domain):
    print_colored(f"\n[+] Gathering URLs passively for: {domain}", colors.BLUE)
    all_raw_urls = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_archive = executor.submit(
            run_command_in_bash,
            f"curl -s -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey' | sort -u"
        )
        future_gau = executor.submit(
            run_command_in_bash,
            f"gau {domain} --threads 10 --subs | sort -u"
        )
        archive_output = future_archive.result()
        if archive_output:
            all_raw_urls.update(archive_output.splitlines())
        else:
            print_colored("[-] No URLs retrieved from Wayback Machine.", colors.YELLOW)
        gau_output = future_gau.result()
        if gau_output:
            all_raw_urls.update(gau_output.splitlines())
        else:
            print_colored("[-] No URLs retrieved from Gau. Make sure Gau is installed and in your PATH.", colors.YELLOW)
    all_raw_urls.add(f"https://{domain}/")
    fuzzable_urls = {url for url in all_raw_urls if is_url_fuzzable(url)}
    print_colored(f"[+] Collected {len(fuzzable_urls)} fuzzable URLs after filtering.", colors.BLUE)
    return list(fuzzable_urls)

def run_fallparams_on_domain(domain, max_length=8):
    print_colored(f"\n[+] Running 'fallparams' for domain: {domain}", colors.BLUE)
    temp_fallparams_output_file_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', prefix="fallparams_output_", suffix=".txt", delete=False) as temp_fallparams_output_file:
            temp_fallparams_output_file_path = temp_fallparams_output_file.name
        fallparams_cmd = f"fallparams -u https://{domain} -silent -o {temp_fallparams_output_file_path}"
        run_command_in_bash(fallparams_cmd, capture_output=False, check=False)
        params = []
        if os.path.exists(temp_fallparams_output_file_path) and os.path.getsize(temp_fallparams_output_file_path) > 0:
            with open(temp_fallparams_output_file_path, 'r', encoding='utf-8') as f:
                fallparams_output_content = f.read()
            params = [p.strip() for p in fallparams_output_content.splitlines() if p.strip()]
        else:
            print_colored("[-] 'fallparams' did not produce any output or command failed. Skipping parameter extraction via fallparams.", colors.YELLOW)
    finally:
        if temp_fallparams_output_file_path and os.path.exists(temp_fallparams_output_file_path):
            try:
                os.remove(temp_fallparams_output_file_path)
            except OSError as e:
                print_colored(f"Error cleaning up file {temp_fallparams_output_file_path}: {e}", colors.RED)
    
    filtered_params = [p for p in params if len(p) <= max_length]
    removed_count = len(params) - len(filtered_params)
    if filtered_params:
        print_colored(f"[+] Found {len(filtered_params)} parameters (after filtering length ≤ {max_length}) from fallparams.", colors.GREEN)
    else:
        print_colored("[-] No parameters passed the length filter from fallparams.", colors.YELLOW)
    if removed_count > 0:
        print_colored(f"[i] {removed_count} parameter(s) were longer than {max_length} characters and were ignored.", colors.CYAN)
    return filtered_params

def standardize_url(url):
    full_url = url
    if not full_url.startswith("http://") and not full_url.startswith("https://"):
        full_url = f"https://{full_url}"
    parsed_url = urlparse(full_url)
    if not parsed_url.query and '%3F' not in full_url.lower():
        if not parsed_url.path.endswith('/') and '.' not in os.path.basename(parsed_url.path):
            full_url = f"{full_url}/"
    return full_url

def get_payloads(args):
    payloads = []
    if args.value_file:
        try:
            with open(args.value_file, 'r', encoding='utf-8') as f:
                payloads.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print_colored(f"ERROR: Could not read value file '{args.value_file}': {e}", colors.RED)
            sys.exit(1)
    if args.value:
        payloads.extend(args.value)
    if not payloads:
        print_colored("[*] Using default fuzzing payloads.", colors.YELLOW)
        return ['"navid"', "'navid'", '<b/navid']
    return list(set(payloads))

def get_parameters(args, dynamic_params=None):
    parameters = []
    if args.parameters:
        try:
            with open(args.parameters, 'r', encoding='utf-8') as f:
                parameters = [line.strip() for line in f if line.strip()]
            print_colored(f"[*] Using parameters from file: {args.parameters}", colors.BLUE)
        except Exception as e:
            print_colored(f"ERROR: Could not read parameters file '{args.parameters}': {e}", colors.RED)
            sys.exit(1)
    else:
        print_colored("[*] Using default parameter list for fuzzing.", colors.YELLOW)
        parameters = [
            'q', 'S', 'search', 'id', 'slug', 'keyword', 'query', 'page', 'keywords',
            'year', 'view', 'email', 'name', 'type', 'n', 'month', 'Image', 'list_type',
            'url', 'pass', 'categoryid', 'key', 'login', 'begindate', 'enddate', 'p',
            'redirect_uri', 'currentURL'
        ]
    if dynamic_params:
        parameters_set = set(parameters)
        parameters_set.update(dynamic_params)
        parameters = list(parameters_set)
        print_colored(f"[*] Merged {len(dynamic_params)} dynamic parameters (from fallparams) with the list.", colors.BLUE)
    return list(set(parameters))

def save_final_results_to_file(results_iterator, output_path):
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for r in results_iterator:
                f.write(r + "\n")
        print_colored(f"\n[+] Saved final generated URLs to: {output_path}", colors.GREEN)
        return output_path
    except Exception as e:
        print_colored(f"ERROR: Could not save final results to {output_path}: {e}", colors.RED)
        return None

class URLGenerator:
    def __init__(self, urls, payloads, parameters, args):
        self.urls = urls
        self.payloads = payloads
        self.parameters = parameters
        self.args = args

    def _generate_urls_chunked(self, urls, payloads, parameters, strategy_func):
        for url in urls:
            for payload in payloads:
                parsed_url = urlparse(url)
                original_query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                if parameters:
                    for i in range(0, len(parameters), self.args.chunk):
                        chunk_params = parameters[i:i + self.args.chunk]
                        yield from strategy_func(url, parsed_url, original_query_params, payload, chunk_params)
                else:
                    yield from strategy_func(url, parsed_url, original_query_params, payload, [])

    def normal_strategy(self, url, parsed_url, original_query_params, payload, current_params_chunk):
        current_params_for_encoding = {}
        for param_name in current_params_chunk:
            current_params_for_encoding[param_name] = payload
        new_query = urlencode(current_params_for_encoding, doseq=True)
        new_parsed_url = parsed_url._replace(query=new_query)
        yield urlunparse(new_parsed_url)

    def ignore_strategy(self, url, parsed_url, original_query_params, payload, current_params_chunk):
        current_params = original_query_params.copy()
        for param_name in current_params_chunk:
            current_params[param_name] = [payload]
        encoded_params = urlencode(current_params, doseq=True)
        updated_url_parts = list(parsed_url)
        updated_url_parts[4] = encoded_params
        yield urlunparse(updated_url_parts)

    def combine_strategy(self, url, parsed_url, original_query_params, payload, current_params_chunk):
        updated_query_params_for_existing = original_query_params.copy()
        for key, values in original_query_params.items():
            if values:
                for i in range(len(values)):
                    if self.args.value_strategy == "suffix":
                        updated_query_params_for_existing[key][i] = values[i] + payload
                    else:
                        updated_query_params_for_existing[key][i] = payload
            else:
                if self.args.value_strategy == "suffix":
                    updated_query_params_for_existing[key] = [payload]
                else:
                    updated_query_params_for_existing[key] = [payload]
        current_combined_params = updated_query_params_for_existing.copy()
        for param_name in current_params_chunk:
            current_combined_params.update({param_name: [payload]})
        encoded_params = urlencode(current_combined_params, doseq=True)
        updated_url_parts = list(parsed_url)
        updated_url_parts[4] = encoded_params
        yield urlunparse(updated_url_parts)

    def generate_urls(self):
        if self.args.generate_strategy == "normal":
            yield from self._generate_urls_chunked(self.urls, self.payloads, self.parameters, self.normal_strategy)
        elif self.args.generate_strategy == "ignore":
            yield from self._generate_urls_chunked(self.urls, self.payloads, self.parameters, self.ignore_strategy)
        elif self.args.generate_strategy == "combine":
            if not self.parameters and self.args.value_strategy == "replace":
                for url in self.urls:
                    for payload in self.payloads:
                        parsed_url = urlparse(url)
                        original_query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                        yield from self.combine_strategy(url, parsed_url, original_query_params, payload, [])
            else:
                yield from self._generate_urls_chunked(self.urls, self.payloads, self.parameters, self.combine_strategy)
        elif self.args.generate_strategy == "all":
            yield from self._generate_urls_chunked(self.urls, self.payloads, self.parameters, self.normal_strategy)
            yield from self._generate_urls_chunked(self.urls, self.payloads, self.parameters, self.ignore_strategy)
            yield from self._generate_urls_chunked(self.urls, self.payloads, self.parameters, self.combine_strategy)

def run_nuclei_batches(generated_urls_iterator, nuclei_template_path, custom_headers, parallel_batches=5, nuclei_concurrency=20, nuclei_rate_limit=150, nuclei_chunk_size=1000):
    print_colored(f"\n[+] Starting Nuclei scans.", colors.BLUE)
    all_nuclei_input_files = []
    temp_dir = tempfile.mkdtemp(prefix="nuclei_chunks_")
    chunk_counter = 0

    try:
        url_chunks = []
        for url in generated_urls_iterator:
            url_chunks.append(url)
            if len(url_chunks) >= nuclei_chunk_size:
                temp_nuclei_input_file_path = os.path.join(temp_dir, f"chunk_{chunk_counter}.txt")
                with open(temp_nuclei_input_file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(url_chunks))
                all_nuclei_input_files.append(temp_nuclei_input_file_path)
                url_chunks = []
                chunk_counter += 1
        if url_chunks:
            temp_nuclei_input_file_path = os.path.join(temp_dir, f"chunk_{chunk_counter}.txt")
            with open(temp_nuclei_input_file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(url_chunks))
            all_nuclei_input_files.append(temp_nuclei_input_file_path)

        if not all_nuclei_input_files:
            print_colored("[-] No URLs generated for Nuclei scan.", colors.YELLOW)
            return

        print_colored(f"[+] Created {len(all_nuclei_input_files)} URL files for Nuclei scanning.", colors.BLUE)
        total_files = len(all_nuclei_input_files)
        print_colored(f"\n[+] Starting Nuclei scans for {total_files} URL files in batches of {parallel_batches}.", colors.BLUE)

        for i in range(0, total_files, parallel_batches):
            current_batch_files = all_nuclei_input_files[i:i + parallel_batches]
            print_colored(f"\n[+] Processing batch {math.ceil((i + 1) / parallel_batches)} of {math.ceil(total_files / parallel_batches)} with {len(current_batch_files)} files...", colors.BLUE)
            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel_batches) as executor:
                futures = []
                for url_file in current_batch_files:
                    nuclei_command = (
                        f"nuclei -t {nuclei_template_path} -silent -l {url_file} "
                        f"-c {nuclei_concurrency} -bs {nuclei_rate_limit} -timeout 3 {custom_headers}"
                    )
                    print_colored(f"[*] Nuclei Command: {nuclei_command}", colors.YELLOW)
                    futures.append(executor.submit(run_command_in_bash, nuclei_command, capture_output=False, check=False))
                for future in concurrent.futures.as_completed(futures):
                    _ = future.result()
    finally:
        for f in all_nuclei_input_files:
            try:
                os.remove(f)
                print_colored(f"[*] Cleaned up temporary Nuclei input file: {f}", colors.NOCOLOR)
            except OSError as e:
                print_colored(f"Error cleaning up file {f}: {e}", colors.RED)
        try:
            os.rmdir(temp_dir)
        except OSError as e:
            print_colored(f"Error cleaning up directory {temp_dir}: {e}", colors.RED)
    
    print_colored("\n[+] All Nuclei scans completed.", colors.GREEN)

def main():
    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter,
                            description="""X9Full: A URL parameter manipulation and fuzzing tool.
    This script passively gathers URLs, extracts parameters, and generates fuzzed URLs
    based on various strategies for security testing.""")
    parser.add_argument('-u', '--url', type=str, help="Single target domain (e.g., example.com) or a full URL to process.")
    parser.add_argument('-l', '--list', type=str, help="Path to a file containing a list of target domains/URLs (one per line).")
    parser.add_argument('-p', '--parameters', type=str,
                            help="Path to a parameter wordlist for fuzzing. If not provided, a default list will be used.")
    parser.add_argument('-c', '--chunk', type=int, default=15,
                            help="Chunk size for grouping parameters during fuzzing. [default: 15]")
    parser.add_argument('-v', '--value', action='append',
                            help='Specific value(s) for parameters to fuzz. Can be used multiple times.')
    parser.add_argument('-f', '--fallparams', action='store_true',
                            help="Run 'fallparams' to gather additional parameters for the target domain(s). Requires 'fallparams' to be installed.")
    parser.add_argument('-vf', '--value_file', type=str,
                            help="Path to a file containing a list of values for parameters to fuzz (one per line).")
    parser.add_argument('-gs', '--generate_strategy',
                            choices=['normal', 'ignore', 'combine', 'all'], default='all',
                            help="""Select the URL generation strategy:
    normal: Removes all existing parameters and replaces with new ones from the wordlist.
    combine: Adds new parameters from the wordlist while keeping existing ones, and modifies existing parameter values.
    ignore: Adds new parameters from the wordlist, ignoring existing ones but not removing them.
    all: Runs all three strategies sequentially.""")
    parser.add_argument('-vs', '--value_strategy', choices=['replace', 'suffix'], default='replace',
                            help="""Select how values are applied (primarily affects 'combine' mode):
    replace: Replaces the existing parameter value with the new payload.
    suffix: Appends the payload to the end of the existing parameter value.""")
    parser.add_argument('-o', '--output', type=str,
                            help="Path to save the final generated URLs. If not provided, URLs are printed to stdout and saved to a temporary file.")
    parser.add_argument('-s', '--silent', action="store_true",
                            help="Silent mode (suppress most console output, except errors).")
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit.')
    parser.add_argument('-np', '--nuclei-parallel', type=int, default=5,
                            help="Number of parallel Nuclei instances to run. [default: 5]")
    parser.add_argument('-ncs', '--nuclei-chunk-size', type=int, default=1000,
                            help="Number of URLs per file for Nuclei chunks. [default: 1000]")
    parser.add_argument('-nc', '--nuclei-concurrency', type=int, default=20,
                            help="Number of concurrent HTTP requests per host for Nuclei. [default: 20]")
    parser.add_argument('-nr', '--nuclei-rate-limit', type=int, default=150,
                            help="Maximum number of requests per second for Nuclei. [default: 150]")
    
    args = parser.parse_args()
    sys.modules['__main__'].args = args

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    try:
        target_domains_or_urls = []
        if args.list:
            try:
                with open(args.list, 'r', encoding='utf-8') as f:
                    target_domains_or_urls.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                print_colored(f"ERROR: Could not read list file '{args.list}': {e}", colors.RED)
                sys.exit(1)
        elif args.url:
            target_domains_or_urls.append(args.url)
        else:
            if not sys.stdin.isatty():
                target_domains_or_urls.extend([line.strip() for line in sys.stdin.readlines() if line.strip()])
            else:
                print_colored("ERROR: No target URL/domain provided. Use -u, -l, or pipe input via stdin.", colors.RED)
                parser.print_help(file=original_stdout)
                sys.exit(1)

        if not target_domains_or_urls:
            print_colored("ERROR: No valid target URLs or domains to process.", colors.RED)
            sys.exit(1)

        all_fuzzable_urls = set()
        all_dynamic_params = set()

        for target in sorted(list(set(target_domains_or_urls))):
            parsed_target = urlparse(target)
            domain_for_passive_gathering = parsed_target.netloc or target
            
            if not domain_for_passive_gathering:
                print_colored(f"Warning: Could not extract a valid domain from '{target}'. Skipping passive URL gathering for this target.", colors.YELLOW)
                continue
            
            if parsed_target.scheme and parsed_target.netloc and parsed_target.query:
                if is_url_fuzzable(target):
                    all_fuzzable_urls.add(standardize_url(target))
            
            gathered_urls = gather_urls_passively(domain_for_passive_gathering)
            all_fuzzable_urls.update(gathered_urls)

            if args.fallparams:
                extracted_params = run_fallparams_on_domain(domain_for_passive_gathering)
                all_dynamic_params.update(extracted_params)

        if not all_fuzzable_urls:
            print_colored("ERROR: No fuzzable URLs were found after gathering and filtering. Exiting.", colors.RED)
            sys.exit(1)

        final_fuzzable_urls_list = list(all_fuzzable_urls)
        
        payloads = get_payloads(args)
        parameters = get_parameters(args, dynamic_params=list(all_dynamic_params))

        if not parameters:
            print_colored("ERROR: No parameters available for fuzzing (neither default, nor from file, nor from fallparams). Exiting.", colors.RED)
            sys.exit(1)

        if not payloads:
            print_colored("ERROR: No payloads available for fuzzing (neither default, nor from file, nor from command line). Exiting.", colors.RED)
            sys.exit(1)

        url_generator = URLGenerator(final_fuzzable_urls_list, payloads, parameters, args)
        generated_urls_iterator = url_generator.generate_urls()
        
        if args.output:
            output_path = args.output
            save_final_results_to_file(generated_urls_iterator, output_path)
            
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, 'r', encoding='utf-8') as f:
                    generated_urls_for_nuclei = [line.strip() for line in f if line.strip()]
            else:
                print_colored("Warning: No URLs were generated or saved to output file. Skipping Nuclei scan.", colors.YELLOW)
                sys.exit(0)
        else:
            temp_output_for_nuclei_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', prefix="x9full_generated_urls_", suffix=".txt") as temp_output_file:
                    temp_output_for_nuclei_path = temp_output_file.name
                    for url in generated_urls_iterator:
                        temp_output_file.write(url + "\n")
                
                print_colored(f"\n[+] Generated URLs saved to temporary file: {temp_output_for_nuclei_path}", colors.BLUE)
                
                with open(temp_output_for_nuclei_path, 'r', encoding='utf-8') as f:
                    generated_urls_for_nuclei = [line.strip() for line in f if line.strip()]
            finally:
                if temp_output_for_nuclei_path and os.path.exists(temp_output_for_nuclei_path):
                    try:
                        os.remove(temp_output_for_nuclei_path)
                    except OSError as e:
                        print_colored(f"Error cleaning up file {temp_output_for_nuclei_path}: {e}", colors.RED)
        
        if not generated_urls_for_nuclei:
            print_colored("Warning: No URLs were generated. This might indicate an issue with your inputs or strategy. Skipping Nuclei scan.", colors.YELLOW)
            sys.exit(0)

        nuclei_template_path = "/home/navid/watch_tower/nuclei/private/xss.yaml"
        if os.path.exists(nuclei_template_path):
            custom_headers = "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9'"
            
            run_nuclei_batches(iter(generated_urls_for_nuclei), nuclei_template_path, custom_headers,
                               parallel_batches=args.nuclei_parallel,
                               nuclei_concurrency=args.nuclei_concurrency,
                               nuclei_rate_limit=args.nuclei_rate_limit,
                               nuclei_chunk_size=args.nuclei_chunk_size)
            
            print_colored("\n[+] All Nuclei scans completed.", colors.GREEN)
        elif not os.path.exists(nuclei_template_path):
            print_colored(f"WARNING: Nuclei template not found at '{nuclei_template_path}'. Skipping Nuclei scan.", colors.YELLOW)
        else:
            print_colored("WARNING: No URLs were generated to scan with Nuclei.", colors.YELLOW)

    except Exception as overall_exception:
        print_colored(f"AN UNEXPECTED SCRIPT ERROR OCCURRED: {overall_exception}", colors.RED)
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr


if __name__ == "__main__":
    main()