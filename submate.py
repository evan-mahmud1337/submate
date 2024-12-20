#!/usr/bin/env python3

import aiohttp
import asyncio
import argparse
import re
import sys


class DomainChecker:
    def __init__(self, input_file=None, output_file=None):
        self.input_file = input_file
        self.output_file = output_file
        self.live_domains = []

    @staticmethod
    def is_valid_domain(domain):
        """
        Validate if a string is a proper domain name or subdomain.
        """
        domain_regex = re.compile(
            r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        )
        return bool(domain_regex.match(domain))

    @staticmethod
    def remove_escape_sequences_and_clean(line):
        """
        Remove ANSI escape sequences and extra whitespace, then extract valid domains.
        """
        # Remove ANSI escape sequences (prefix and suffix)
        ansi_escape = re.compile(r'\x1b\[\d{1,2}m')  # Matches any ANSI escape sequence
        cleaned_line = ansi_escape.sub('', line).strip()

        # Extract domain-like substrings after removing color codes
        domain_match = re.search(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", cleaned_line)
        if domain_match:
            return domain_match.group(1)
        return None

    async def check_domain(self, domain):
        """
        Check if a domain is live.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}", timeout=20) as response:
                    if response.status in [200, 301]:
                        print(f"[LIVE] {domain}")
                        self.live_domains.append(domain)
                    else:
                        pass
        except aiohttp.ClientError as ex:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception as ex:
            pass

    async def run_checks(self, domains):
        """
        Run checks for all domains concurrently.
        """
        print(f"Checking {len(domains)} domains...\n")
        tasks = [self.check_domain(domain) for domain in domains]
        await asyncio.gather(*tasks)

    def read_domains(self):
        """
        Read domains from input file or piped input, and validate them.
        """
        raw_domains = []
        if self.input_file:
            with open(self.input_file, "r") as file:
                raw_domains = [line.strip() for line in file.readlines()]
        elif not sys.stdin.isatty():
            raw_domains = [line.strip() for line in sys.stdin.readlines()]
        else:
            print("Error: No input provided. Use -f or pipe input to the script.")
            sys.exit(1)

        # Clean, extract, and filter valid domains as sublister and some tools uses banner before stdout
        cleaned_domains = filter(
            None,
            (self.remove_escape_sequences_and_clean(line) for line in raw_domains)
        )
        valid_domains = [
            domain for domain in cleaned_domains if self.is_valid_domain(domain)
        ]
        print(f"Found {len(valid_domains)} valid domains.\n")
        return valid_domains

    def save_live_domains(self):
        """
        Save live domains to the output file if specified.
        """
        if self.output_file:
            with open(self.output_file, "w") as file:
                file.write("\n".join(self.live_domains))
            print(f"\nLive domains saved to '{self.output_file}'.")

    async def main(self):
        """
        Main function to run the domain checker.
        """
        domains = self.read_domains()
        await self.run_checks(domains)
        self.save_live_domains()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check the live status of subdomains asynchronously.")
    parser.add_argument("-f", "--file", help="File containing the list of subdomains")
    parser.add_argument("-o", "--output", help="Output file to save live domains")
    args = parser.parse_args()

    checker = DomainChecker(input_file=args.file, output_file=args.output)

    try:
        asyncio.run(checker.main())
        print(f"Total live domains {len(checker.live_domains)}")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
