from gc import get_objects

from docling.document_converter import DocumentConverter
from docling_core.transforms.chunker import HierarchicalChunker
from langchain_community.llms import Ollama
from langchain_core.prompts import PromptTemplate
import rdflib
from rdflib.plugins.sparql.algebra import triples

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
    return uri.split("#")[-1]

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
llm = Ollama(model="mistral")


malont_classes = [get_label(cls) for cls in classes]
malont_objects = [get_label(obj) for obj in object_properties]





prompt = PromptTemplate.from_template(f"""
You are a cybersecurity analyst.

From the text below, extract all cybersecurity-relevant knowledge in the form of subject-predicate-object triples.

Use only the following known entity types:
{', '.join(malont_classes[:15])}

Use only the following known relationship types:
{', '.join(malont_objects[:15])}

Output each triple as a JSON object with "subject", "predicate", and "object" fields.

Return an array of triples. No commentary, no text, just valid JSON.

Text:
\"\"\"{{text}}\"\"\"
""")


chain = prompt | llm

# Step 4: Run through each hierarchical chunk
triples = set()
for i in chunks:
    response = chain.invoke({"text": i})
    triples.add(response)
    print(triples)