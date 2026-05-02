## Progress

This Markdown file documents progress made in generating code

for the FOSRES project. 

Claude Code Sonnet 4.6 was used to help generate raw software

files. You can see the ongoing conversation here:

```
https://claude.ai/share/71a81505-a49f-4fee-b2cd-d3ff09009af9
```

Mistral (Le Chat Pro) was used to audit files. You will see

links to the conversations below where relevant. 



1. Generate project directory structure

This text file gives the files and directories that house the

files for the FOSRES webapp.

It can be found in:

```
AppSec-Exercises/p2p/fosres_directory_structure_complete.txt
```

For now the structure is more complicated than we care to audit.

Instead I want to now talk about the required files from the

directory structure relevant for authenticating clients when they

login to FOSRES.

1. First  let's focus on the files from the directory structure

that are required to run `master_key_gen` (mentioned in 

`p2p_authentication_revised_second_edition.md`).

The relevant files are highlighted in the document

```
AppSec-Exercises/p2p/authentication/master_key_gen_required_files.txt
```

So I first downloaded the `package.json` Claude generated. You can

find it in:

```
AppSec-Exercises/p2p/fosres/frontend/package.json
```


Since we are dealing with Angular (Typescript version of AngularJS)

we consult the "OWASP NPM Security Best Practices".

In order I will check for the following:

	1. Avoid publishing secrets to the npm registry.

	I so far found no secrets published in the `package.json`

	I also tried asking Mistral to find any. None found.

	You can see the Mistral conversation below:

	```
	https://chat.mistral.ai/chat/bfaa4053-e000-400c-b568-c0896618d2c9
	```
	I also decided to make a GitHub Actions 
