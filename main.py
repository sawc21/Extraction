
import json
from docling.document_converter import DocumentConverter
from docling_core.transforms.chunker import HierarchicalChunker
from langchain_community.llms import Ollama



class CyberTripleExtractor:
    def __init__(self, file_path, model_name="tinyllama"):
        self.file_path = file_path
        self.converter = DocumentConverter()
        self.chunker = HierarchicalChunker()
        self.llm = Ollama(model=model_name)

        self.malont_classes = [
            'Staging', 'Adware', 'CommandAndControl', 'Spyware', 'DDoS', 'DomainName', 'Dropper', 'Port', 'MD5',
            'Protocol', 'VirusScanner', 'Downloader', 'Ransomware', 'OperatingSystem', 'Rootkit',
            'AttackPattern_SmallDescription', 'IPAddress', 'Bootkit', 'Hardware', 'SSDeep',
            'Application', 'AttackPattern', 'Phishing', 'Campaign', 'SHA-256', 'System',
            'Vulnerability_Desc', 'Anonymization', 'Backdoor', 'Location', 'Organization',
            'Reconnaissance', 'Exploit-kit', 'Time', 'MalwareAnalysis', 'ResourceExploitation',
            'SHA', 'HostingMalware', 'SHA-1', 'Unknown', 'HostingTargetLists', 'Hash',
            'AttackPattern_LargeDescription', 'Software', 'Network', 'Indicator', 'Trojan', 'Botnet',
            'Worm', 'EmailAddress', 'Malware', 'RogueSecuritySoftware', 'vHash', 'Filepath', 'Region',
            'Report', 'Virus', 'ThreatActor', 'Keylogger', 'Browser', 'ScreenCapture',
            'Vulnerability_CVEID', 'URL', 'Wiper', 'Filename', 'Infrastructure', 'MalwareFamily',
            'Person', 'Webshell', 'Vulnerability', 'Bot', 'RemoteAccessTrojan-RAT', 'Country',
            'Exfiltration', 'Amplification'
        ]
        self.malont_objects = [
            "targets", "communicatesWith", "uses", "has", "hasAlias",
            "hasVulnerability", "indicates", "exploits", "hasAuthor", "belongsTo"
        ]

        self.prompt_template = f"""
        You are a cybersecurity analyst.

        From the text below, extract all cybersecurity-relevant knowledge in the form of subject-predicate-object triples.

        Use only these entity types or ones who can relate:
        {", ".join(self.malont_classes)}

        Use only these relationship types or ones that can relate:
        {", ".join(self.malont_objects)}

        Output as a JSON array of objects with keys: "subject", "predicate", "object".

        Do not add any explanation. Just return valid JSON.

        Now extract from this:
        \"\"\"{{text}}\"\"\"
        """

        self.valid_triples = []

    def run(self):
        print("Loading and converting document...")
        result = self.converter.convert(self.file_path)
        doc = result.document

        print("Chunking document...")
        chunks = list(self.chunker.chunk(dl_doc=doc))

        print("Extracting triples...")
        for i, chunk in enumerate(chunks):
            print(f"\n--- Chunk {i + 1} ---")
            try:
                prompt = self.prompt_template.replace("{{text}}", str(chunk))
                response = self.llm.invoke(prompt)
                triples = json.loads(response)
                for t in triples:
                    if self._is_valid_triple(t):
                        self.valid_triples.append(t)
                        print(f"{t['subject']} —{t['predicate']}→ {t['object']}")
                    else:
                        print(f"Suspicious triple: {t}")
            except Exception as e:
                print(f"Error parsing chunk {i + 1}: {e}")

        return self.valid_triples

    def _is_valid_triple(self, triple):
        return (
            triple.get("predicate") in self.malont_objects and
            any(cls.lower() in triple.get("subject", "").lower() for cls in self.malont_classes)
        )



if __name__ == "__main__":
    extractor = CyberTripleExtractor("sample1.pdf")
    triples = extractor.run()

    print("\nExtracted Triples:")
    for t in triples:
        print(f"{t['subject']} —{t['predicate']}→ {t['object']}")
