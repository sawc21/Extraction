

from docling.document_converter import DocumentConverter
from docling_core.transforms.chunker import HierarchicalChunker
from langchain_community.llms import Ollama
from langchain_core.prompts import PromptTemplate
import rdflib
import json


# Load the OWL file
ontology_path = 'MALOnt/MALOnt.owl'  # Path to your OWL file
g = rdflib.Graph()
g.parse(ontology_path)

# Define namespaces
namespace_owl = rdflib.URIRef("http://www.w3.org/2002/07/owl#")
namespace_rdfs = rdflib.URIRef("http://www.w3.org/2000/01/rdf-schema#")
namespace_malont = rdflib.URIRef("http://idea.rpi.edu/malont#")


def get_label(uri):
    for _, _, label in g.triples((uri, rdflib.RDFS.label, None)):
        return str(label)
    uri_str = str(uri)
    return uri_str.split("#")[-1] if "#" in uri_str else uri_str.split("/")[-1]


# 1. Extract Classes (Entities) from the ontology
classes = set()
for s, p, o in g.triples((None, rdflib.RDF.type, rdflib.OWL.Class)):
    classes.add(s)

for cls in classes:
    label = get_label(cls)
    comment = next((str(c) for _, _, c in g.triples((cls, rdflib.RDFS.comment, None))), "")


# 2. Extract Object Properties (Relationships) from the ontology
object_properties = set()
for s, p, o in g.triples((None, rdflib.RDF.type, rdflib.OWL.ObjectProperty)):
    object_properties.add(s)





# Step 1: Load Docling document
converter = DocumentConverter()
result = converter.convert("sample1.pdf")
doc = result.document

# Step 2: Create Hierarchical Chunker
chunker = HierarchicalChunker()
chunks = list(chunker.chunk(dl_doc=doc))

# Step 3: Set up Ollama + Prompt
llm = Ollama(model="tinyllama")


malont_classes = [get_label(cls) for cls in classes]
malont_objects = [get_label(obj) for obj in object_properties]
malont_class_str = ", ".join(malont_classes[:15])
malont_object_str = ", ".join(malont_objects[:15])

prompt = PromptTemplate.from_template("""
You are a cybersecurity analyst.

From the text below, extract all cybersecurity-relevant knowledge in the form of subject-predicate-object triples.

Use only these entity types:
{{malont_classes}}

Use only these relationship types:
{{malont_objects}}

Output as a JSON array of objects with keys: "subject", "predicate", "object".

Do not add any explanation. Just return valid JSON.

---
Example 1:
Text:
"APT28 used the Outlook vulnerability CVE-2017-11774 to target government agencies."

Output:
[
  {{
    "subject": "APT28",
    "predicate": "uses",
    "object": "CVE-2017-11774"
  }},
  {{
    "subject": "APT28",
    "predicate": "targets",
    "object": "government agencies"
  }}
]

Now extract from this:
\"\"\"{{text}}\"\"\"
""")





chain = prompt.partial(
    malont_classes=malont_class_str,
    malont_objects=malont_object_str
) | llm


# Step 4: Run through each hierarchical chunk
triples = set()
valid_triples = []
for i, chunk in enumerate(chunks):
    print(f"\n--- Chunk {i + 1} ---")
    response = chain.invoke({"text": chunk})

    try:
        json_output = json.loads(response)
        for t in json_output:
            print(f"[✓] {t['subject']} —{t['predicate']}→ {t['object']}")
            triples.add((t['subject'], t['predicate'], t['object']))
            if t['predicate'] in malont_objects and any(ent in t['subject'] for ent in malont_classes):
                valid_triples.append(t)
            else:
                print("[!] Suspicious triple:", t)
    except (json.JSONDecodeError, ValueError) as e:

        print("[!] Could not parse output:")
        print(response)

