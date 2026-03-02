from pypdf import PdfReader
import io
import json

def extract_text_from_pdf(file_bytes):
    """Extracts raw text from a PDF file."""
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        text = ""
        for page in reader.pages:
            content = page.extract_text()
            if content:
                text += content
        return text.lower()
    except Exception as e:
        print(f"DEBUG PARSER: Text extraction failed: {e}")
        return ""

def calculate_match_score(resume_text, job_skills_data):
    """
    Compares resume text against job skills.
    Handles both JSON strings and Python lists.
    """
    if not resume_text or not job_skills_data:
        return 0
    
    resume_text = resume_text.lower()
    
    # Handle different data types for skills
    if isinstance(job_skills_data, str):
        try:
            job_skills = json.loads(job_skills_data)
        except:
            # Fallback: if it's a comma-separated string
            job_skills = [s.strip() for s in job_skills_data.split(',')]
    else:
        job_skills = job_skills_data

    if not job_skills:
        return 0
    
    match_count = 0
    for skill in job_skills:
        if skill.lower() in resume_text:
            match_count += 1
            
    score = int((match_count / len(job_skills)) * 100)
    print(f"DEBUG MATCHER: Found {match_count}/{len(job_skills)} matches. Score: {score}%")
    return score