# CSCE3550-Project2

This project was completed with the assistance of Github Copilot and Gemini.
The following prompts were used to aid in development of this project (This list is not exhaustive and may not include prompts or automatic suggestions by Github Copilot):

- What are some of the database drivers for python?
- What are methods to prevent SQL injection when working with JWKS servers?
- How to generate different types of keys?
- How can I improve the security of my JWKS server?
- What are some example tests to generate for the coverage of my server?
- How to ensure keys are encrypted and decrypted correctly?
- What should I be checking for when I generate and select private keys (SQL)?

# Requirements
- Setup Virtual envrionment on VScode or terminal and execution of project must be in .venv (virtual environment)
- Download python 3.13.7
- Install packages (listed in requirements.txt)using pip 

# Instructions to run (with gradebot)
1. After cloning project, navigate into CSCE3550-Project2 (root folder)
2. Activate virtual environment (assuming python 3.13.7 is installed) using "python3 -m venv venv" then "source venv/bin/activate" - steps might be different for activating virtual environment based on OS
3. Make sure packages are installed, can manually install using pip install -r requirements.txt
4. After completing requirements, run "python app.py" on terminal line,
then proceed to use gradebot (project2) to check against rubric
5. To run test suite, install packages using "pip install pytest pytest-cov" and delete previous database generate. Then run "python test_project.py"
Notes*
Gradebot must be in project root directory
Files include whether AI assistance was used