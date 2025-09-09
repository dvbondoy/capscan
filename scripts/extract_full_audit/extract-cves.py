import re
import PyPDF2

def extract_cves_from_pdf(pdf_path):
    # Regex pattern for CVE format (CVE-YYYY-NNNN+)
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

    cves = set()  # use set to avoid duplicates

    # Open PDF
    with open(pdf_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)

        for page_num in range(len(reader.pages)):
            text = reader.pages[page_num].extract_text()
            if text:
                matches = cve_pattern.findall(text)
                cves.update(matches)

    return sorted(cves)


if __name__ == "__main__":
    pdf_file = "nexpose-metasploitable-test.pdf"  # replace with your PDF filename
    found_cves = extract_cves_from_pdf(pdf_file)
    output_file = "nextpose_metasploitable2_cves.txt"
    total = len(found_cves)

    if found_cves:
        print("Found CVEs:")
        for cve in found_cves:
            print(cve)
        
        print(f"Total CVEs: {total}")
        
        # Save to text file
        with open(output_file, "w") as f:
            f.write(f"Total CVEs found: {total}\n\n")
            for cve in found_cves:
                f.write(cve + "\n")

        print(f"Results saved to {output_file}")
    else:
        print("No CVEs found in the PDF.")
