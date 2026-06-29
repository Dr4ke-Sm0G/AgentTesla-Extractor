# -*- coding: utf-8 -*-
"""
Advanced AgentTesla Configuration Extractor | Industrial Grade
------------------------------------------------------------
extractor for AgentTesla .NET payloads.
includes Anti-Analysis Bypass (Watchdog/Timeout).

Features: 
    - OOP Structure
    - Robust Error Handling & Watchdog
    - Statistical Outlier Removal
    - JSON Export
    - Safe Threaded Invocation
"""

import sys
import os
import argparse
import json
import logging
import statistics
import threading
from datetime import datetime

# Setup basic logging layout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("AgentTeslaExtractor")

# Dependency Check & Loading
try:
    import clr
except ImportError:
    logger.critical("Module 'pythonnet' is missing. Install it via: pip install pythonnet")
    sys.exit(1)

class AgentTeslaExtractor:
    def __init__(self, file_path, dnlib_path, timeout=2, verbose=False):
        self.file_path = os.path.abspath(file_path)
        self.dnlib_path = os.path.abspath(dnlib_path)
        self.timeout = timeout  # Max seconds to wait for malware decryption
        self.verbose = verbose
        self.results = {
            "metadata": {
                "filename": os.path.basename(self.file_path),
                "timestamp": datetime.now().isoformat(),
                "analysis_tool": "AdvancedAgentTeslaExtractor_v2"
            },
            "extracted_config": [],
            "all_strings": []
        }

        # Whitelist filters (Legitimate domains used for IP checks)
        self.ignored_domains = [
            "dyn.com", "ipify.org", "checkip.amazonaws.com", 
            "whatismyipaddress.com", "ident.me", "ip-api.com",
            "microsoft.com", "google.com"
        ]

        self._load_dependencies()

    def _load_dependencies(self):
        """Loads the .NET environment and dnlib reference."""
        if not os.path.exists(self.dnlib_path):
            logger.critical(f"dnlib.dll not found at: {self.dnlib_path}")
            sys.exit(1)
        
        try:
            clr.AddReference("System")
            clr.AddReference(self.dnlib_path)
            
            # Late imports after CLR load
            global dnlib, OpCodes, Int32, ModuleDefMD, Assembly
            import dnlib
            from dnlib.DotNet import ModuleDefMD
            from dnlib.DotNet.Emit import OpCodes
            from System import Int32
            from System.Reflection import Assembly
            
            if self.verbose: logger.info("Dependencies loaded successfully.")
        except Exception as e:
            logger.critical(f"Failed to load .NET references: {str(e)}")
            sys.exit(1)

    def _load_modules(self):
        """Loads the target file as both Dnlib Module and Reflection Assembly."""
        if not os.path.exists(self.file_path):
            logger.error(f"Target file not found: {self.file_path}")
            sys.exit(1)

        try:
            self.dn_module = ModuleDefMD.Load(self.file_path)
            # CAUTION: This loads the assembly into memory.
            self.ref_module = Assembly.LoadFile(self.file_path)
            
            if self.verbose: logger.info(f"Loaded module: {self.dn_module.Name}")
        except Exception as e:
            logger.error(f"Failed to load target executable. Is it a valid .NET PE? Error: {e}")
            sys.exit(1)

    def _get_decryption_method_token(self):
        """Identifies the decryption method via Signature (Int32 -> String)."""
        tokens = []
        try:
            for type_def in self.dn_module.GetTypes():
                if not type_def.HasMethods: continue
                
                for method in type_def.Methods:
                    if method.MethodSig is None: continue
                    if len(method.Parameters) != 1: continue
                    
                    param_type = method.Parameters[0].Type.FullName
                    return_type = method.ReturnType.FullName
                    
                    if param_type == "System.Int32" and return_type == "System.String":
                        if method.IsStatic:
                            tokens.append(method.MDToken.ToInt32())
        except Exception as e:
            logger.warning(f"Error during method enumeration: {e}")
        return tokens

    def _get_ldc_keys(self):
        """Extracts Ldc_I4 values pushed before a Call instruction."""
        values = []
        try:
            for type_def in self.dn_module.GetTypes():
                for method in type_def.Methods:
                    if not method.HasBody: continue
                    
                    instructions = method.Body.Instructions
                    for i in range(len(instructions) - 1):
                        curr_instr = instructions[i]
                        next_instr = instructions[i+1]
                        
                        if curr_instr.OpCode == OpCodes.Ldc_I4 and next_instr.OpCode == OpCodes.Call:
                            val = curr_instr.Operand
                            if isinstance(val, int) and val not in values:
                                values.append(val)
        except Exception as e:
            logger.error(f"Error parsing IL instructions: {e}")
        return values

    def _filter_statistical_outliers(self, values):
        """Removes values that are statistically unlikely to be valid keys."""
        if not values: return []
        try:
            val_median = statistics.median(values)
            variance = abs(val_median * 0.1) 
            cleaned = [v for v in values if (val_median - variance) <= abs(v) <= (val_median + variance)]
            
            if self.verbose:
                logger.info(f"Statistical Clean: Kept {len(cleaned)}/{len(values)} keys.")
            return cleaned
        except statistics.StatisticsError:
            return values

    def _is_c2_data(self, string_val):
        """Filters strings to find likely C2 configuration."""
        if not string_val or len(string_val) < 4: return False
        
        is_suspicious = "http" in string_val or ".com" in string_val or "smtp" in string_val or "ftp" in string_val
        is_whitelisted = any(domain in string_val for domain in self.ignored_domains)
        
        return is_suspicious and not is_whitelisted

    def _invoke_with_timeout(self, method, arg):
        """
        Safely invokes a method with a timeout using threading.
        Prevents the script from hanging on anti-analysis loops.
        """
        result_container = {"output": None, "exception": None}

        def target():
            try:
                # Actual execution of malware code
                result_container["output"] = method.Invoke(None, (Int32(arg),))
            except Exception as e:
                result_container["exception"] = e

        # Daemon thread dies when main program dies
        thread = threading.Thread(target=target)
        thread.daemon = True 
        thread.start()
        
        # Wait for the thread to finish or timeout
        thread.join(self.timeout)

        if thread.is_alive():
            # If thread is still alive after join, it timed out.
            # We cannot kill it easily in Python, but we can ignore it and move on.
            return None, TimeoutError(f"Execution timed out (> {self.timeout}s)")
        
        return result_container["output"], result_container["exception"]

    def run(self):
        """Main execution flow."""
        self._load_modules()
        logger.info("Starting Industrial Analysis...")
        
        method_tokens = self._get_decryption_method_token()
        if not method_tokens:
            logger.error("No decryption method matching signature found.")
            return

        raw_keys = self._get_ldc_keys()
        clean_keys = self._filter_statistical_outliers(raw_keys)
        logger.info(f"Targeting {len(method_tokens)} methods with {len(clean_keys)} keys.")

        decrypted_count = 0
        for token in method_tokens:
            try:
                target_method = self.ref_module.ManifestModule.ResolveMethod(token)
            except Exception:
                continue

            for key in clean_keys:
                # --- SAFE INVOCATION ---
                result, error = self._invoke_with_timeout(target_method, key)
                
                if isinstance(error, TimeoutError):
                    if self.verbose: logger.warning(f"Watchdog triggered on key {key}: skipping.")
                    continue
                elif error:
                    continue # Ignore standard invocation errors
                
                if result:
                    str_result = str(result)
                    self.results["all_strings"].append(str_result)
                    
                    if self._is_c2_data(str_result):
                        if str_result not in self.results["extracted_config"]:
                            self.results["extracted_config"].append(str_result)
                            logger.info(f"[+] DETECTED: {str_result}")
                            decrypted_count += 1
        
        if decrypted_count == 0:
            logger.warning("Analysis finished. No C2 found (Try --dump-all to see everything).")

    def export_json(self, output_path):
        """Exports results to a JSON file."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Report exported: {output_path}")
        except IOError as e:
            logger.error(f"JSON Export failed: {e}")

# -------------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------------
def main():
    banner = r"""
    =======================================================
      AGENT TESLA EXTRACTOR 
    =======================================================
    """
    print(banner)

    parser = argparse.ArgumentParser(description="Industrial AgentTesla Config Extractor")
    parser.add_argument('-f', '--file', required=True, help="Path to the AgentTesla payload")
    parser.add_argument('-d', '--dnlib', default="dnlib.dll", help="Path to dnlib.dll")
    parser.add_argument('-o', '--output', help="JSON Output path")
    parser.add_argument('-t', '--timeout', type=int, default=2, help="Max seconds per decryption call (Default: 2s)")
    parser.add_argument('--dump-all', action='store_true', help="Export all strings")
    parser.add_argument('-v', '--verbose', action='store_true', help="Debug logging")

    args = parser.parse_args()
    
    if args.verbose: logger.setLevel(logging.DEBUG)

    extractor = AgentTeslaExtractor(args.file, args.dnlib, args.timeout, args.verbose)
    extractor.run()

    # Summary
    print("\n" + "="*30)
    print(" FINAL INTELLIGENCE REPORT ")
    print("="*30)
    
    if extractor.results["extracted_config"]:
        for conf in extractor.results["extracted_config"]:
            print(f" [!] IoC: {conf}")
    else:
        print(" [-] No critical IoCs found.")

    if args.output or extractor.results["extracted_config"]:
        out_file = args.output if args.output else f"{os.path.basename(args.file)}_report.json"
        extractor.export_json(out_file)

if __name__ == "__main__":
    main()