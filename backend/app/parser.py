from pypdf import PdfReader
import io
import json

def extract_text_from_pdf(file_bytes):
    """Extracts raw text from a PDF file for matching purposes."""
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        text = ""
        for page in reader.pages:
            content = page.extract_text()
            if content:
                text += content
        return text.lower()
    except Exception as e:
        print(f"Parsing error: {e}")
        return ""

def calculate_match_score(resume_text, job_skills_json):
    """Compares resume text against job skills and returns a percentage."""
    if not resume_text:
        return 0
    
    try:
        # Convert the job_skills string back to a list
        job_skills = json.loads(job_skills_json)
    except:
        return 0

    if not job_skills or len(job_skills) == 0:
        return 0
    
    match_count = 0
    for skill in job_skills:
        if skill.lower() in resume_text:
            match_count += 1
            
    return int((match_count / len(job_skills)) * 100)