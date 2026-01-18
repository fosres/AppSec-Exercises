---
title: "Can You Spot the Bugs? 35 C Security Code Review Challenges"
published: false
description: "Test your security skills with real vulnerable C code. Complete answer key included."
tags: security, c, programming, cybersecurity
---

# Can You Spot the Security Bugs? 35 C Code Review Challenges 🔍

## The $370 Million Bug

June 4, 1996. After a decade of development and $7 billion in investment, the Ariane 5 rocket lifted off on its maiden voyage. 37 seconds later, it exploded.

The cause? A single line of C code.

```c
// Converting 64-bit float to 16-bit signed integer
horizontal_bias = (int16_t) horizontal_velocity;
```

The horizontal velocity exceeded the maximum value a 16-bit integer could hold. Integer overflow. The guidance system crashed. The rocket's self-destruct sequence activated. $370 million gone in an instant.

This wasn't an obscure edge case. It was a **predictable C language vulnerability** that code review should have caught.

---

## Why This Matters for Security Engineers

Similar bugs have caused:

- **Heartbleed (2014):** Buffer over-read in OpenSSL leaked millions of passwords and private keys
- **WannaCry (2017):** Buffer overflow in Windows SMB caused global ransomware outbreak affecting 200,000+ computers
- **Stagefright (2015):** Integer overflow in Android media library enabled remote code execution on 950 million devices
- **Dirty COW (2016):** Race condition in Linux kernel granted attackers root access on millions of servers

**Every one of these was a C language-level vulnerability that code review should have prevented.**

This is why **Security Engineering interviews test your ability to audit C code and write secure implementations.** Companies need engineers who can spot these bugs before they reach production.

---

## The Challenge

Below are **35 vulnerable C code snippets**. Each contains real vulnerability patterns found in production code.

**Your mission:**

1. 🔍 Identify ALL security vulnerabilities in each snippet
2. 💡 Explain the root cause
3. ✅ Write a secure implementation

**Time limit per exercise:** 20 minutes

**This is what Security Engineering interviews look like.** No hints. No guidance. Just you and the code.

Complete solutions with detailed explanations are provided at the end.

🔗 **Full exercises available at: [SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises)**

---

## ⭐ Before You Start: Star the Repo

If you find these exercises useful, **please star the repo!**

🔗 **[⭐ Star SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises)**

Your stars help others discover these security exercises and motivate me to create more content.

---

## Vulnerable Code Snippets

### 1. Exercise 6: C Security Audit - Log Message Builder

**File:** `Exercise_6_ACME_Style_sizeof_Bug.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *build_log_message(const char *prefix, const char *message) {
	size_t prefix_len = strlen(prefix);
	size_t message_len = strlen(message);
	char *log = (char *) malloc(prefix_len + message_len);
	strcpy(log, prefix);
	strcat(log, message);
	return log;
}
int main() {
	const char *timestamp = "[2024-01-15] ";
	const char *user_msg = "Login successful";
	char *log_entry = build_log_message(timestamp, user_msg);
	printf("%s\n", log_entry);
	free(log_entry);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 2. Exercise 7: C Security Audit - Substring Extraction

**File:** `Exercise_7_ACME_Style_Substring.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *extract_substring(const char *source, int start, int end) {
	int length = end - start;
	char *result = (char *) malloc(length);
	for (int i = 0; i < length; i++) {
		result[i] = source[start + i];
	}
	return result;
}
int main() {
	const char *text = "Hello, World!";
	char *substring = extract_substring(text, 7, 12);
	printf("Substring: %s\n", substring);
	free(substring);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 3. Exercise 8: C Security Audit - Configuration Key Parser

**File:** `Exercise_8_ACME_Style_strncpy.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define MAX_KEY_SIZE 32
int parse_config_key(const char *line, char *key_buffer) {
	const char *equals = strchr(line, '=');
	if (equals == NULL) {
		return -1;
	}
	size_t key_len = equals - line;
	if (key_len > MAX_KEY_SIZE) {
		return -1;
	}
	strncpy(key_buffer, line, key_len);
	return 0;
}
int main() {
	char key[MAX_KEY_SIZE];
	const char *config = "database_host=localhost";
	if (parse_config_key(config, key) == 0) {
		printf("Key: %s\n", key);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 4. Exercise 9: C Security Audit - Log Message Builder

**File:** `Exercise_9_ACME_Style_strncat.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define LOG_BUFFER_SIZE 64
void build_log(char *buffer, const char *user_message) {
	const char *timestamp = "[2024-01-15 10:30:00] ";
	strcpy(buffer, timestamp);
	NULL-termination. 
	strncat(buffer, user_message, LOG_BUFFER_SIZE);
}
int main() {
	char log[LOG_BUFFER_SIZE];
	const char *message = "User login successful";
	build_log(log, message);
	printf("Log: %s\n", log);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 5. Exercise 10: C Security Audit - User Input Parser

**File:** `Exercise_10_ACME_Style_scanf.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define USERNAME_SIZE 32
int read_username(char *username) {
	printf("Enter username: ");
	scanf("%s", username);
	return 0;
}
int main() {
	char user[USERNAME_SIZE];
	read_username(user);
	printf("Welcome, %s!\n", user);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 6. Exercise 11: C Security Audit - Password Input Reader

**File:** `Exercise_11_ACME_Style_gets.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define PASSWORD_SIZE 64
int read_password(char *password) {
	printf("Enter password: ");
	gets(password);
	return 0;
}
int main() {
	char pass[PASSWORD_SIZE];
	read_password(pass);
	printf("Password length: %zu\n", strlen(pass));
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 7. Exercise 12: C Security Audit - String Concatenator

**File:** `Exercise_12_ACME_Style_Integer_Overflow.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *concat_strings(const char *str1, const char *str2) {
	size_t len1 = strlen(str1);
	size_t len2 = strlen(str2);
	size_t total_size = len1 + len2 + 1;
	char *result = malloc(total_size);
	strcpy(result, str1);
	strcat(result, str2);
	return result;
}
int main() {
	char *combined = concat_strings("Hello, ", "World!");
	if (combined != NULL) {
		printf("%s\n", combined);
		free(combined);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 8. Exercise 13: C Security Audit - Code Review

**File:** `Exercise_13_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
int32_t *allocate_array(size_t num_elements) {
	size_t total_bytes = num_elements * sizeof(int32_t);
	int32_t *array = malloc(total_bytes);
	return array;
}
int main() {
	size_t count = 1000;
	int32_t *data = allocate_array(count);
	if (data != NULL) {
		printf("Allocated array of %zu elements\n", count);
		free(data);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 9. Exercise 14: C Security Audit - Code Review

**File:** `Exercise_14_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *remove_prefix(const char *str, size_t prefix_len) {
	size_t str_len = strlen(str);
	size_t result_len = str_len - prefix_len;
	char *result = malloc(result_len + 1);
	strcpy(result, str + prefix_len);
	return result;
}
int main() {
	const char *text = "Hello, World!";
	char *without_prefix = remove_prefix(text, 7);
	if (without_prefix != NULL) {
		printf("Result: %s\n", without_prefix);
		free(without_prefix);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 10. Exercise 15: C Security Audit - Code Review

**File:** `Exercise_15_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
int copy_buffer(uint8_t *dest, size_t dest_size, const uint8_t *src, int src_len) {
	if (src_len > dest_size) {
		return -1;
	}
	memcpy(dest, src, src_len);
	return 0;
}
int main() {
	uint8_t destination[64];
	uint8_t source[32] = "Hello, World!";
	int result = copy_buffer(destination, sizeof(destination), source, 13);
	if (result == 0) {
		printf("Copy successful\n");
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 11. Exercise 16: C Security Audit - Code Review

**File:** `Exercise_16_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
int find_element(int *array, int array_size, int target) {
	for (int i = 0; i < array_size; i++) {
		if (array[i] == target) {
			return i;
		}
	}
	return -1;
}
int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	int index = find_element(numbers, 5, 30);
	if (index != -1) {
		printf("Found at index: %d\n", index);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 12. Exercise 17: C Security Audit - Code Review

**File:** `Exercise_17_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void reverse_string(char *str) {
	size_t len = strlen(str);
	for (size_t i = 0; i < len; i++) {
		char temp = str[i];
		str[i] = str[len - i];
		str[len - i] = temp;
	}
}
int main() {
	char text[] = "Hello";
	reverse_string(text);
	printf("Reversed: %s\n", text);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 13. Exercise 18: C Security Audit - Code Review

**File:** `Exercise_18_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int *merge_arrays(int *array1, size_t size1, int *array2, size_t size2) {
	size_t total_size = size1 + size2;
	int *result = malloc(total_size);
	memcpy(result, array1, size1);
	memcpy(result + size1, array2, size2);
	return result;
}
int main() {
	int first[] = {1, 2, 3};
	int second[] = {4, 5, 6};
	int *merged = merge_arrays(first, 3, second, 3);
	if (merged != NULL) {
		printf("Merged array created\n");
		free(merged);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 14. Exercise 19: C Security Audit - Code Review

**File:** `Exercise_19_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *duplicate_string(const char *src, size_t max_len) {
	size_t len = strlen(src);
	if (len > max_len) {
		len = max_len;
	}
	char *result = calloc(len, sizeof(char));
	gurantee NULL-termination
	strncpy(result, src, len);
	return result;
}
int main() {
	const char *original = "Hello, World!";
	char *copy = duplicate_string(original, 10);
	if (copy != NULL) {
		printf("Copy: %s\n", copy);
		free(copy);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 15. Exercise 20: C Security Audit - Code Review

**File:** `Exercise_20_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *get_config_value(const char *key, int value) {
	char buffer[64];
	snprintf(buffer, sizeof(buffer), "%s=%d", key, value);
	return buffer;
}
int main() {
	char *config = get_config_value("timeout", 30);
	printf("Config: %s\n", config);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 16. Exercise 21: C Security Audit - Code Review

**File:** `Exercise_21_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
double compute_average(int *values, size_t count) {
	int sum = 0;
	for (size_t i = 0; i < count; i++) {
		sum += values[i];
	}
	return sum / count;
}
int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	double avg = compute_average(numbers, 5);
	printf("Average: %.2f\n", avg);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 17. Exercise 22: C Security Audit - Code Review

**File:** `Exercise_22_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
char *to_lowercase(const char *str) {
	if (str == NULL) {
		return NULL;
	}
	size_t len = strlen(str);
	char *result = calloc(len + 1, sizeof(char));
	if (result == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < len; i++) {
		result[i] = tolower(str[i]);
	}
	return result;
}
int main() {
	char *lower1 = to_lowercase("HELLO");
	char *lower2 = to_lowercase("WORLD");
	if (lower1 != NULL && lower2 != NULL) {
		printf("%s %s\n", lower1, lower2);
	}
	free(lower1);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 18. Exercise 23: C Security Audit - Code Review

**File:** `Exercise_23_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
bool all_positive(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return false;
	}
	bool result;
	for (size_t i = 0; i < count; i++) {
		if (values[i] <= 0) {
			result = false;
			break;
		}
	}
	return result;
}
int main() {
	int numbers[] = {1, 2, 3, 4, 5};
	if (all_positive(numbers, 5)) {
		printf("All values are positive\n");
	} else {
		printf("Not all values are positive\n");
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 19. Exercise 24: C Security Audit - Code Review

**File:** `Exercise_24_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
size_t find_max_index(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return 0;
	}
	size_t max_index = 0;
	for (size_t i = 1; i <= count; i++) {
		if (values[i] > values[max_index]) {
			max_index = i;
		}
	}
	return max_index;
}
int main() {
	int numbers[] = {10, 50, 30, 20, 40};
	size_t max_idx = find_max_index(numbers, 5);
	printf("Max value is at index: %zu\n", max_idx);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 20. Exercise 25: C Security Audit - Code Review

**File:** `Exercise_25_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {
	char *name;
	char *description;
} Resource;
void cleanup_resource(Resource *res) {
	if (res == NULL) {
		return;
	}
	if (res->name != NULL) {
		free(res->name);
	}
	if (res->description != NULL) {
		free(res->description);
	}
	free(res);
}
int main() {
	Resource *r = calloc(1, sizeof(Resource));
	r->name = calloc(20, sizeof(char));
	strcpy(r->name, "Config");
	r->description = r->name;
	cleanup_resource(r);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 21. Exercise 26: C Security Audit - Code Review

**File:** `Exercise_26_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int *extract_range(int *source, size_t source_size, size_t start, size_t end) {
	if (source == NULL) {
		return NULL;
	}
	size_t range_size = end - start;
	int *result = calloc(range_size, sizeof(int));
	if (result == NULL) {
		return NULL;
	}
	memcpy(result, source + start, range_size * sizeof(int));
	return result;
}
int main() {
	int numbers[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
	int *subset = extract_range(numbers, 10, 2, 5);
	if (subset != NULL) {
		printf("Extracted: %d %d %d\n", subset[0], subset[1], subset[2]);
		free(subset);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 22. Exercise 27: C Security Audit - Code Review

**File:** `Exercise_27_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
bool check_permission(const char *username, const char *required_role) {
	if (username == NULL || required_role == NULL) {
		return false;
	}
	char *user_role = NULL;
	if (strcmp(username, "admin") = 0) {
		user_role = "admin";
	} else if (strcmp(username, "user") = 0) {
		user_role = "user";
	} else {
		user_role = "guest";
	}
	if (strcmp(user_role, required_role) == 0) {
		return true;
	}
	return false;
}
int main() {
	if (check_permission("admin", "admin")) {
		printf("Access granted\n");
	} else {
		printf("Access denied\n");
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 23. Exercise 28: C Security Audit - Code Review

**File:** `Exercise_28_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {
	char *first_name;
	char *last_name;
	int age;
} User;
User *find_user(const char *username) {
	if (strcmp(username, "john") == 0) {
		User *u = calloc(1, sizeof(User));
		u->first_name = "John";
		u->last_name = "Doe";
		u->age = 30;
		return u;
	}
	return NULL;
}
void print_user_info(const char *username) {
	User *user = find_user(username);
	printf("Name: %s %s, Age: %d\n", 
		user->first_name, 
		user->last_name, 
		user->age);
	free(user);
}
int main() {
	print_user_info("john");
	print_user_info("alice");
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 24. Exercise 29: C Security Audit - Code Review

**File:** `Exercise_29_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *format_log_message(const char *level, const char *message) {
	if (level == NULL || message == NULL) {
		return NULL;
	}
	char buffer[64];
	sprintf(buffer, "[%s] %s", level, message);
	char *result = calloc(strlen(buffer) + 1, sizeof(char));
	if (result == NULL) {
		return NULL;
	}
	strcpy(result, buffer);
	return result;
}
int main() {
	char *log1 = format_log_message("INFO", "System started");
	char *log2 = format_log_message("ERROR", "Connection failed");
	if (log1 != NULL) {
		printf("%s\n", log1);
		free(log1);
	}
	if (log2 != NULL) {
		printf("%s\n", log2);
		free(log2);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 25. Exercise 30: C Security Audit - Code Review

**File:** `Exercise_30_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int get_matrix_element(int *matrix, size_t rows, size_t cols, size_t row, size_t col) {
	if (matrix == NULL) {
		return -1;
	}
	size_t index = row * cols + col;
	return matrix[index];
}
int main() {
	int matrix[3][4] = {
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12}
	};
	printf("Element at (1, 2): %d\n", get_matrix_element((int*)matrix, 3, 4, 1, 2));
	printf("Element at (2, 3): %d\n", get_matrix_element((int*)matrix, 3, 4, 2, 3));
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 26. Exercise 31: C Security Audit - Code Review

**File:** `Exercise_31_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int *copy_array(int *source, size_t count) {
	if (source == NULL || count == 0) {
		return NULL;
	}
	int *result = malloc(sizeof(source));
	if (result == NULL) {
		return NULL;
	}
	memcpy(result, source, sizeof(source));
	return result;
}
int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	int *copy = copy_array(numbers, 5);
	if (copy != NULL) {
		printf("Copied array: ");
		for (int i = 0; i < 5; i++) {
			printf("%d ", copy[i]);
		}
		printf("\n");
		free(copy);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 27. Exercise 32: C Security Audit - Code Review

**File:** `Exercise_32_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
char *pad_string(const char *str, size_t width) {
	if (str == NULL || width == 0) {
		return NULL;
	}
	size_t len = strlen(str);
	if (len >= width) {
		return strdup(str);
	}
	char *result = calloc(width, sizeof(char));
	if (result == NULL) {
		return NULL;
	}
	strcpy(result, str);
	for (size_t i = len; i <= width; i++) {
		result[i] = ' ';
	}
	return result;
}
int main() {
	char *padded = pad_string("Hello", 10);
	if (padded != NULL) {
		printf("Padded: '%s'\n", padded);
		free(padded);
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 28. Exercise 33: C Security Audit - Code Review

**File:** `Exercise_33_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
void count_letters(const char *text) {
	if (text == NULL) {
		return;
	}
	int counts[26] = {0};
	for (size_t i = 0; i < strlen(text); i++) {
		char c = tolower(text[i]);
		int index = c - 'a';
		counts[index]++;
	}
	printf("Letter frequencies:\n");
	for (int i = 0; i < 26; i++) {
		if (counts[i] > 0) {
			printf("%c: %d\n", 'a' + i, counts[i]);
		}
	}
}
int main() {
	count_letters("Hello World!");
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 29. Exercise 34: C Security Audit - Code Review

**File:** `Exercise_34_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void write_integers(unsigned char *buffer, int *data, size_t count) {
	if (buffer == NULL || data == NULL || count == 0) {
		return;
	}
	for (size_t i = 0; i < count; i++) {
		buffer[i] = data[i];
	}
}
int main() {
	int numbers[] = {0x12345678, 0xABCDEF00, 0x11223344};
	unsigned char buffer[12];
	write_integers(buffer, numbers, 3);
	printf("Buffer contents: ");
	for (int i = 0; i < 12; i++) {
		printf("%02X ", buffer[i]);
	}
	printf("\n");
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 30. Exercise 35: C Security Audit - Code Review

**File:** `Exercise_35_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
typedef enum {
	ROLE_GUEST,
	ROLE_USER,
	ROLE_ADMIN
} UserRole;
bool check_access(UserRole role, const char *resource) {
	if (resource == NULL) {
		return false;
	}
	bool can_access = false;
	switch (role) {
		case ROLE_GUEST:
			if (strcmp(resource, "public") == 0) {
				can_access = true;
			}
		case ROLE_USER:
			if (strcmp(resource, "documents") == 0) {
				can_access = true;
			}
		case ROLE_ADMIN:
			if (strcmp(resource, "settings") == 0) {
				can_access = true;
			}
	}
	return can_access;
}
int main() {
	printf("Guest accessing public: %s\n", 
		check_access(ROLE_GUEST, "public") ? "ALLOWED" : "DENIED");
	printf("Guest accessing settings: %s\n", 
		check_access(ROLE_GUEST, "settings") ? "ALLOWED" : "DENIED");
	printf("User accessing documents: %s\n", 
		check_access(ROLE_USER, "documents") ? "ALLOWED" : "DENIED");
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 31. Exercise 34: C Security Audit - Code Review

**File:** `Exercise_36_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {
	char hostname[32];
	int port;
} Config;
void set_hostname(Config *config, const char *hostname) {
	if (config == NULL || hostname == NULL) {
		return;
	}
	strncpy(config->hostname, hostname, sizeof(config->hostname));
}
int main() {
	Config config;
	config.port = 8080;
	set_hostname(&config, "server.example.com");
	printf("Hostname: %s\n", config.hostname);
	printf("Port: %d\n", config.port);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 32. Exercise 37: C Security Audit - Code Review

**File:** `Exercise_37_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int read_buffer(unsigned char *buffer, size_t buffer_size, int offset, unsigned char *output, size_t output_size) {
	if (buffer == NULL || output == NULL) {
		return -1;
	}
	if (offset < 0 || offset >= buffer_size) {
		return -1;
	}
	if (output_size > buffer_size - offset) {
		return -1;
	}
	memcpy(output, buffer + offset, output_size);
	return 0;
}
int main() {
	unsigned char data[100];
	for (int i = 0; i < 100; i++) {
		data[i] = i;
	}
	unsigned char result[10];
	if (read_buffer(data, 100, 50, result, 10) == 0) {
		printf("Read succeeded: ");
		for (int i = 0; i < 10; i++) {
			printf("%d ", result[i]);
		}
		printf("\n");
	}
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 33. Exercise 38: C Security Audit - Code Review

**File:** `Exercise_38_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {
	char *name;
	char *value;
} ConfigEntry;
ConfigEntry *create_config(const char *name, const char *value) {
	if (name == NULL || value == NULL) {
		return NULL;
	}
	ConfigEntry *entry = malloc(sizeof(ConfigEntry));
	if (entry == NULL) {
		return NULL;
	}
	entry->name = strdup(name);
	entry->value = strdup(value);
	return entry;
}
int update_config(ConfigEntry *entry, const char *new_value) {
	if (entry == NULL || new_value == NULL) {
		return 1;
	}
	free(entry->value);
	entry->value = strdup(new_value);
	return 0;
}
void free_config(ConfigEntry *entry) {
	if (entry == NULL) {
		return;
	}
	free(entry->name);
	free(entry->value);
	free(entry);
}
int main() {
	ConfigEntry *config = create_config("hostname", "localhost");
	printf("Initial: %s = %s\n", config->name, config->value);
	update_config(config, "server.example.com");
	printf("Updated: %s = %s\n", config->name, config->value);
	free_config(config);
	return 0;
}
```

**❓ What vulnerabilities can you find?**

---

### 34. ACME Product Security Tech Test - Question 1

**File:** `Exercise_39_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
char *deserialize(const char *s) {
	size_t len = strnlen(s, 4096);
	char *b = (char *) malloc(len);
	strcpy(b, s);
	return b;
}
```

**❓ What vulnerabilities can you find?**

---

### 35. ACME Product Security Tech Test - Question 1

**File:** `ACME_Question_1.md`

```c
#include <stdlib.h>
#include <string.h>
char *deserialize(const char *s) {
	size_t len = strnlen(s, 4096);
	char *b = (char *) malloc(len);
	strcpy(b, s);
	return b;
}
```

**❓ What vulnerabilities can you find?**

---

# 🔑 Answer Key: Secure Implementations

Below are the complete secure implementations with detailed comments explaining each fix.

**Note:** These solutions include comprehensive security analysis, showing the thought process behind identifying and fixing each vulnerability.

---

## Solution 1: Exercise 6: C Security Audit - Log Message Builder

**File:** `Exercise_6_ACME_Style_sizeof_Bug.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *build_log_message(const char *prefix, const char *message) {

	if ( prefix == NULL )
	{
		fprintf(stderr,"Error: prefix == NULL\n");

		return NULL;
	}
	
	if ( message == NULL )
	{
		fprintf(stderr,"Error: message == NULL\n");

		return NULL;
	}

	size_t prefix_len = strlen(prefix);
	size_t message_len = strlen(message);


	char *log = (char *) calloc(prefix_len + message_len + 1,sizeof(char));

	if ( log == NULL )
	{
		fprintf(stderr,"Error: allocation of log failed\n");

		return NULL;
	}

	snprintf(log,prefix_len + message_len + 1,"%s%s",prefix,message);

	return log;
}

int main() {
	const char *timestamp = "[2024-01-15] ";
	const char *user_msg = "Login successful";
	
	char *log_entry = build_log_message(timestamp, user_msg);
	
	if ( log_entry == NULL )
	{
		fprintf(stderr,"Error: log_entry == NULL\n");	

		return 1;
	}

	printf("%s\n", log_entry);
	
	free(log_entry);
	return 0;
}
```

---

## Solution 2: Exercise 7: C Security Audit - Substring Extraction

**File:** `Exercise_7_ACME_Style_Substring.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *extract_substring(const char *source, size_t start, size_t end) {
	
	/*
		Integer Overflow/Underflow Vulnerability:

		Depending on signedness of `start` and `end` the 

		below calcualation of length either results in

		a negative number as the correct difference (which

		is nonsensical for a length calculation) or

		a result of integer overflow/underflow.

		There is also no check if both `end` and `start`

		are positive and end > start.

		Never use a signed integer for counting objects.

		Use an unsigned data type such as `size_t` instead.
	*/

	if ( source == NULL )
	{
		fprintf(stderr,"Error: source == NULL\n");

		return NULL;
	}

	if ( end <= start )
	{
		fprintf(stderr,"Error: end <= start\n");

		return NULL;
	}
	
	if ( end > strlen(source) )
	{
		fprintf(stderr,"Error: end > strlen(source)\n");

		return NULL;
	}
	
	size_t length = end - start;

	// Off-By-One: No gurantee of sufficient space for

	// NULL-termination below in malloc() calculation

	// Also failure to check if malloc() returns NULL
	
	char *result = (char *) calloc(length+1,sizeof(char));

	if ( result == NULL )
	{
		fprintf(stderr,"Error: allocation of result failed!\n");

		return NULL;
	}

	// What if length below is negative?	

	memcpy(result,source + start,length);

	return result;
}

int main() {
	const char *text = "Hello, World!";
	
	// Extract "World" (positions 7-12)
	
	// No check if extract_substring() returns a NULL string

	char *substring = extract_substring(text, 7, 12);

	if ( substring == NULL )
	{
		fprintf(stderr,"Error: extract_substring() returns NULL\n");

		return 1;
	}
	
	printf("Substring: %s\n", substring);
	
	free(substring);

	return 0;
}
```

---

## Solution 3: Exercise 8: C Security Audit - Configuration Key Parser

**File:** `Exercise_8_ACME_Style_strncpy.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_KEY_SIZE 32

int parse_config_key(const char *line, char *key_buffer) {

	// No check if line is a NULL pointer.

	if ( line == NULL )
	{
		fprintf(stderr,"Error: line == NULL\n");

		return -1;
	}		

	const char *equals = strchr(line, '=');
	
	if (equals == NULL) {
		return -1;
	}
	
	size_t key_len = equals - line;
	
	// No guarantee of NULL-termination below in strncpy()

	// because key_len == MAX_KEY_SIZE possible
	
	if (key_len >= MAX_KEY_SIZE) {
		return -1;
	}

	// No guarantee of NULL-termination below in strncpy()

	// because key_len == MAX_KEY_SIZE possible
	
	strncpy(key_buffer, line, key_len);

	key_buffer[key_len] = 0x00;
	
	return 0;
}

int main() {
	char key[MAX_KEY_SIZE];
	const char *config = "database_host=localhost";
	
	if (parse_config_key(config, key) == 0) {
		printf("Key: %s\n", key);
	}
	
	return 0;
}
```

---

## Solution 4: Exercise 9: C Security Audit - Log Message Builder

**File:** `Exercise_9_ACME_Style_strncat.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_BUFFER_SIZE 64


void build_log(char *buffer, const char *user_message) {
	
	const char *timestamp = "[2024-01-15 10:30:00] ";

	// Possible concatenation below exceeds bounds of buffer
	
	if (user_message == NULL)
	{
		fprintf(stderr,"Error: user_message == NULL\n");

		return;
	}

	size_t len = strlen(timestamp) + strlen(user_message);

	if ( len >= LOG_BUFFER_SIZE )
	{
		fprintf(stderr,"Error: len >= LOG_BUFFER_SIZE\n");

		return;
	}

	if ( buffer == NULL )
	{
		fprintf(stderr,"Error: buffer == NULL\n");

		return;
	}

	snprintf(buffer,LOG_BUFFER_SIZE,"%s%s",timestamp,user_message);
	
}

int main() {
	char log[LOG_BUFFER_SIZE];
	const char *message = "User login successful";
	
	build_log(log, message);
	printf("Log: %s\n", log);
	
	return 0;
}
```

---

## Solution 5: Exercise 10: C Security Audit - User Input Parser

**File:** `Exercise_10_ACME_Style_scanf.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define USERNAME_SIZE 32

int read_username(char *username) {

	// No check if username == NULL

	if ( username == NULL )
	{
		fprintf(stderr,"Error: username == NULL\n");

		return -1;
	}
	
	printf("Enter username: ");

	// Buffer Overflow: User input can be equal to or larger than USERNAME_SIZE

	// Which leaves no room for proper NULL-termination

	uint8_t c = 0;

	size_t i = 0;

	for (  ; i < USERNAME_SIZE - 1 ; i++ )
	{
		c = fgetc(stdin);

		if ( c == 0x0a )
		{
			break;
		}		
		
		username[i] = c;
	}

	username[i] = 0x00;

//	scanf("%s", username);

	return 0;
}

int main() {
	char user[USERNAME_SIZE];
	
	read_username(user);
	printf("Welcome, %s!\n", user);
	
	return 0;
}
```

---

## Solution 6: Exercise 11: C Security Audit - Password Input Reader

**File:** `Exercise_11_ACME_Style_gets.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PASSWORD_SIZE 64

int read_password(char *password) {
	
	// No check if password == NULL

	if ( password == NULL )
	{
		fprintf(stderr,"Error: password == NULL\n");

		return 1;
	}
	
	printf("Enter password: ");
	
	// gets() will read more characters than PASSWORD_SIZE - 1 
	// until newline or EOF	

	// Also there is no attempt to NULL-terminate password after

	// calling gets()

	size_t i = 0;

	int c = 0;

	for ( ; i < PASSWORD_SIZE - 1 ; i++ )
	{
		c = fgetc(stdin);

		if ( c == '\n' || c == EOF )
		{
			break;
		}	
		
		password[i] = c;
	}

	password[i] = 0x00;
	
	return 0;
}

int main() {
	char pass[PASSWORD_SIZE];
	
	read_password(pass);
	printf("Password length: %zu\n", strlen(pass));
	
	return 0;
}
```

---

## Solution 7: Exercise 12: C Security Audit - String Concatenator

**File:** `Exercise_12_ACME_Style_Integer_Overflow.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *concat_strings(const char *str1, const char *str2) {

	if ( str1 == NULL  )
	{
		fprintf(stderr,"Error: str1 == NULL\n");

		return NULL;

	}
	
	if ( str2 == NULL  )
	{
		fprintf(stderr,"Error: str2 == NULL\n");

		return NULL;

	}

	
	size_t len1 = strlen(str1);

	size_t len2 = strlen(str2);
	
	// size_t total_size = len1 + len2 + 1;

	size_t total_size = 0;

	if ( __builtin_add_overflow(len1,len2,&total_size) == true )
	{
		fprintf(stderr,"Error: len1 + len2 is integer overflow\n");

		return NULL;
	}

	size_t one = 1;
	
	if ( __builtin_add_overflow(total_size,one,&total_size) == true )
	{
		fprintf(stderr,"Error: len1 + len2 + 1 is integer overflow\n");

		return NULL;
	}

	// No check if malloc() returns NULL 	
	
	char *result = malloc(total_size);

	if ( result == NULL )
	{
		fprintf(stderr,"Error: result == NULL\n");

		return NULL;
	}
	
	strcpy(result, str1);
	strcat(result, str2);

	return result;
}

int main() {
	char *combined = concat_strings("Hello, ", "World!");
	
	if (combined != NULL) {
		printf("%s\n", combined);
		free(combined);
	}
	
	return 0;
}
```

---

## Solution 8: Exercise 13: C Security Audit - Code Review

**File:** `Exercise_13_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

int32_t *allocate_array(size_t num_elements) {

	// NO check if below multiplication causes Integer Overflow

//	size_t total_bytes = num_elements * sizeof(int32_t);

	size_t total_bytes = 0;

	if ( __builtin_mul_overflow(num_elements,sizeof(int32_t),&total_bytes) ==
true )
	{
		fprintf(stderr,"Error: total_bytes calculation overflows\n");

		return NULL;
	}

	// No check if malloc() below returns NULL pointer	

	int32_t *array = malloc(total_bytes);

	if ( array == NULL )
	{
		fprintf(stderr,"Error: array allocation failed\n");

		return NULL;
	}
	
	return array;
}

int main() {
	size_t count = 1000;
	int32_t *data = allocate_array(count);
	
	if (data != NULL) {
		printf("Allocated array of %zu elements\n", count);
		free(data);
	}
	
	return 0;
}
```

---

## Solution 9: Exercise 14: C Security Audit - Code Review

**File:** `Exercise_14_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *remove_prefix(const char *str, size_t prefix_len) {

	if ( str == NULL )
	{
		fprintf(stderr,"Error: str == NULL\n");

		return NULL;

	}

	// No check if prefix_len == 0

	if ( prefix_len == 0 )
	{
		fprintf(stderr,"Error: prefix_len == 0\n");

		return NULL;
	}

	size_t str_len = strlen(str);

	if ( prefix_len >= str_len )
	{
		fprintf(stderr,"Error: prefix_len >= str_len\n");
	
		return NULL;
	}

	// No check for Integer Underflow below

	// No check if prefix_len >= str_len

//	size_t result_len = str_len - prefix_len;

	size_t result_len = 0;

	if ( __builtin_sub_overflow(str_len,prefix_len,&result_len) == true )
	{
		fprintf(stderr,"Error: str_len - prefix_len underflows\n");

		return NULL;
	}

	// No check if malloc() returns NULL below 
	
	char *result = malloc(result_len + 1);

	// NULL-termination in strcpy() only takes place if

	// NULL-terminating byte present in str

	if ( result == NULL )
	{
		fprintf(stderr,"result == NULL\n");

		return NULL;
	}

	snprintf(result,result_len + 1,"%s",str + prefix_len);
	
	return result;
}

int main() {
	const char *text = "Hello, World!";

	char *without_prefix = remove_prefix(text, 7);
	
	if (without_prefix != NULL) {
		printf("Result: %s\n", without_prefix);
		free(without_prefix);
	}
	
	return 0;
}
```

---

## Solution 10: Exercise 15: C Security Audit - Code Review

**File:** `Exercise_15_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// src_len can be negative! Use size_t instead

int copy_buffer(uint8_t *dest, size_t dest_size, const uint8_t *src,size_t src_len) {
	
	// No NULL pointer checks for dest and src	

	if ( dest == NULL || src == NULL )
	{
		return -1;
	}
	
	
	if (src_len > dest_size) {
		return -1;
	}

	memcpy(dest, src, src_len);
	
	return 0;
}

int main() {
	uint8_t destination[64];
	uint8_t source[32] = "Hello, World!";
	
	int result = copy_buffer(destination, sizeof(destination), source, 13);
	
	if (result == 0) {
		printf("Copy successful\n");
	}
	
	return 0;
}
```

---

## Solution 11: Exercise 16: C Security Audit - Code Review

**File:** `Exercise_16_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// instead of int use size_t
size_t find_element(int *array, size_t array_size, int target) {

	// No check if array == NULL

	if ( array == NULL )
	{
		return array_size;
	}

	// array_size can be negative. Should be size_t

	// size_t should be used for counting elements below in loop
	
	for (size_t i = 0; i < array_size; i++) {
		if (array[i] == target) {
			return i;
		}
	}

	// instead of returning -1 return size of array	
	return array_size;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	// index can be negative. Should be of data type size_t

	size_t index = find_element(numbers, 5, 30);
	
	if (index != sizeof(numbers) / sizeof(int) ) {
		printf("Found at index: %zu\n", index);
	}
	
	return 0;
}
```

---

## Solution 12: Exercise 17: C Security Audit - Code Review

**File:** `Exercise_17_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// No check if str == NULL
void reverse_string(char *str) {

	
	// No check if str == NULL

	if ( str == NULL )
	{
		return;
	}

	size_t len = strlen(str);

	if ( len == 0 )
	{
		return;
	}

	/* 
		Out-of-bounds indexing.	
	
		For example when i == 0 

		len - 0 == len. But you

		cannot index str[len]
	*/

	for (size_t i = 0, j = len - 1 ; i < j ; i++,j--) {
		char temp = str[i];
		str[i] = str[j];
		str[j] = temp;
	}
}

int main() {
	char text[] = "Hello";
	reverse_string(text);
	
	printf("Reversed: %s\n", text);
	
	return 0;
}
```

---

## Solution 13: Exercise 18: C Security Audit - Code Review

**File:** `Exercise_18_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int *merge_arrays(int *array1, size_t size1, int *array2, size_t size2) {

	// No Check if array1 == NULL || array2 == NULL

	if ( array1 == NULL || array2 == NULL )
	{
		return NULL;
	}

	// No check if total_size == 0

	// Integer Overflow Vulnerability Below
	
	size_t total_size = 0;

	
	if ( __builtin_add_overflow(size1,size2,&total_size) == true )
	{
		return NULL;
	}

	if ( total_size == 0 )
	{
		return NULL;
	}
	// No check if malloc() returns NULL

	// incorrect amount of multiplication	
	int *result = malloc(total_size * sizeof(int));

	if ( result == NULL )
	{
		return NULL;
	}
	

	memcpy(result, array1, size1 * sizeof(int));
	memcpy(result + size1, array2, size2 * sizeof(int));
	
	return result;
}

int main() {
	int first[] = {1, 2, 3};
	int second[] = {4, 5, 6};
	
	int *merged = merge_arrays(first, 3, second, 3);
	
	if (merged != NULL) {
		printf("Merged array created\n");
		free(merged);
	}
	
	return 0;
}
```

---

## Solution 14: Exercise 19: C Security Audit - Code Review

**File:** `Exercise_19_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *duplicate_string(const char *src, size_t max_len) {

	// No check is src == NULL

	if ( src == NULL )
	{
		return NULL;
	}

	size_t len = strlen(src);

	if (len > max_len) {
		len = max_len;
	}

	// No check if result == NULL after calloc()

	// Off-By-One Error possible since we need space

	// for terminating NULL-byte: should be calloc(len+1,...
	
	char *result = calloc(len+1, sizeof(char));

	if ( result == NULL )
	{
		return NULL;
	}
	// Since src string can be truncated below does not

	gurantee NULL-termination
	
	strncpy(result, src, len);

	result[len] = 0x00; // in case src is truncated this is needed
	
	return result;
}

int main() {
	const char *original = "Hello, World!";
	char *copy = duplicate_string(original, 10);
	
	if (copy != NULL) {
		printf("Copy: %s\n", copy);
		free(copy);
	}
	
	return 0;
}
```

---

## Solution 15: Exercise 20: C Security Audit - Code Review

**File:** `Exercise_20_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *get_config_value(const char *key, int value) {

	if ( key == NULL )
	{
		return NULL;
	}

	// No check if key == NULL

	// Not a security vulnerability since snprintf() copies

	// at most sizeof(buffer) - 1 bytes but will mention

	// anyway:

	// possible truncation of key if too large to fit in

	// buffer before NULL-byte
	
	// buffer is popped from stack after function call

	// instance ends. You will have to use dynamic memory

	// allocation and free the buffer later!

	// Below allocation should gurantee enough space since int

	// values cannot be larger than 11 characters long

	// so total_len == 11 (len of value string at worst) + strlen(key) + 1 ('=')

	// so total_len == strlen(key) + 12

	// but alloc_len for buffer must be total_len + 1 to leave

	// space for terminating NULL-byte

	size_t total_len = 0;

	size_t twelve = 12;

	if ( __builtin_add_overflow(strlen(key),twelve,&total_len) == true )
	{
		return NULL;
	}

	size_t one = 1;

	size_t alloc_len = 0;
	
	if ( __builtin_add_overflow(total_len,one,&alloc_len) == true )
	{
		return NULL;
	}

	char * buffer = (char*)calloc(alloc_len,sizeof(char));

	if ( buffer == NULL )
	{
		return NULL;
	}

	// have to add 1 to total_len to gurantee space for NULL-byte
	
	snprintf(buffer,alloc_len, "%s=%d", key, value);
	
	return buffer;
}

int main() {
	
	// No error checking that get_config_value returns NULL

	char *config = NULL;

	if ( ( config = get_config_value("timeout",30) ) == NULL )
	{
		return 1;
	}
	
	printf("Config: %s\n", config);

	free(config);
	
	return 0;
}
```

---

## Solution 16: Exercise 21: C Security Audit - Code Review

**File:** `Exercise_21_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

double compute_average(int *values, size_t count) {

	// No check if values == NULL

	if ( values == NULL )
	{
		return 0.0;
	}
	
	// Problem no check if count == 0. You cannot divide by zero.

	if ( count == 0 )
	{
		return 0.0;
	}

	// Problem: sum is of type int but the return data

	// type is double

	// sum is of type double

	double sum = 0;
	
	for (size_t i = 0; i < count; i++) {

		// risk of Integer Overflow below

		sum += values[i];
	}

	// Problem: count is of type size_t whereas sum

	// is of type int
	
	return sum / count;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	double avg = compute_average(numbers, 5);
	
	printf("Average: %.2f\n", avg);
	
	return 0;
}
```

---

## Solution 17: Exercise 22: C Security Audit - Code Review

**File:** `Exercise_22_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

char *to_lowercase(const char *str) {
	if (str == NULL) {
		return NULL;
	}
	
	size_t len = strlen(str);
	char *result = calloc(len + 1, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}
	
	for (size_t i = 0; i < len; i++) {
		result[i] = tolower(str[i]);
	}
	
	return result;
}

int main() {
	char *lower1 = to_lowercase("HELLO");
	char *lower2 = to_lowercase("WORLD");
	
	if (lower1 != NULL && lower2 != NULL) {
		printf("%s %s\n", lower1, lower2);
	}
	
	// We need to check which of lower1 or lower2 is NOT NULL

	// and free that accordingly so below free() is not sufficient

	if ( lower1 != NULL )
	{
		free(lower1);
	}

	if ( lower2 != NULL )
	{
		free(lower2);
	}
	
	return 0;
}
```

---

## Solution 18: Exercise 23: C Security Audit - Code Review

**File:** `Exercise_23_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

bool all_positive(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return false;
	}

	// result not initialized so unsafe to return as uninitialized
		
	for (size_t i = 0; i < count; i++) {

		if (values[i] <= 0) {
			
			return false;	
		}
	}
	
	return true;
}

int main() {
	int numbers[] = {1, 2, 3, 4, 5};
	
	if (all_positive(numbers, 5)) {
		printf("All values are positive\n");
	} else {
		printf("Not all values are positive\n");
	}
	
	return 0;
}
```

---

## Solution 19: Exercise 24: C Security Audit - Code Review

**File:** `Exercise_24_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

size_t find_max_index(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return 0;
	}
	
	size_t max_index = 0;

	// Out-of-bounds: you can't access values[count]
	
	for (size_t i = 1; i < count; i++)
	{

		if (values[i] > values[max_index])
		{
			max_index = i;
		}
	}
	
	return max_index;
}

int main() {
	int numbers[] = {10, 50, 30, 20, 40};
	
	size_t max_idx = find_max_index(numbers, 5);
	
	printf("Max value is at index: %zu\n", max_idx);
	
	return 0;
}
```

---

## Solution 20: Exercise 25: C Security Audit - Code Review

**File:** `Exercise_25_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char *name;
	char *description;
} Resource;

void cleanup_resource(Resource *res) {
	if (res == NULL) {
		return;
	}
	
	if (res->name != NULL) {
		free(res->name);
	}

	// Remember res->description = res->name in main()

	// free() does not gurantee pointer is assigned

	// NULL afterwards! Double-free vulnerability below!

	// Check if res->description != res->name in addition to NULL
	
	if ( res->description != NULL  ) {
		free(res->description);
	}
	
	free(res);
}

int main() {

	// No check if r == NULL

	Resource *r = calloc(1, sizeof(Resource));

	if ( r == NULL )
	{
		return 1;
	}	
	
	r->name = calloc(20, sizeof(char));
	
	// No check if r->name == NULL

	if ( r->name == NULL )
	{
		cleanup_resource(r);

		return 1;
	}

	// Danger: below strcpy can cause a buffer overflow

	snprintf(r->name,20*sizeof(char),"%s","Config");

	//strcpy(r->name, "Config");

	// Below can easily lead to a double-free vulnerability
	
	r->description = calloc(20, sizeof(char));
	
	// No check if r->name == NULL

	if ( r->description == NULL )
	{
		cleanup_resource(r);

		return 1;
	}

	snprintf(r->description,20*sizeof(char),"%s",r->name);	
	
	cleanup_resource(r);
	
	return 0;
}
```

---

## Solution 21: Exercise 26: C Security Audit - Code Review

**File:** `Exercise_26_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int *extract_range(int *source, size_t source_size, size_t start, size_t end) {
	if (source == NULL) {
		return NULL;
	}

	// No check if end <= start

	if ( end <= start )
	{
		return NULL;
	}

	// No check if start  >= source_size and end <= source_size

	if ( end > source_size || start >= source_size )
	{
		return NULL;
	}
	
	size_t range_size = end - start;
	
	int *result = calloc(range_size, sizeof(int));
	
	if (result == NULL) {
		return NULL;
	}
	
	memcpy(result, source + start, range_size * sizeof(int));
	
	return result;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
	
	int *subset = extract_range(numbers, 10, 2, 5);
	
	if (subset != NULL) {
		printf("Extracted: %d %d %d\n", subset[0], subset[1], subset[2]);
		free(subset);
	}
	
	return 0;
}
```

---

## Solution 22: Exercise 27: C Security Audit - Code Review

**File:** `Exercise_27_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

bool check_permission(const char *username, const char *required_role) {
	if (username == NULL || required_role == NULL) {
		return false;
	}
	
	char *user_role = NULL;

	// supposed to be == 0	
	if (strcmp(username, "admin") == 0) {
		user_role = "admin";
	
	// supposed to be == 0	
	} else if (strcmp(username, "user") == 0) {
		user_role = "user";
	} else {
		user_role = "guest";
	}
	
	if (strcmp(user_role, required_role) == 0) {
		return true;
	}
	
	return false;
}

int main() {
	if (check_permission("admin", "admin")) {
		printf("Access granted\n");
	} else {
		printf("Access denied\n");
	}
	
	return 0;
}
```

---

## Solution 23: Exercise 28: C Security Audit - Code Review

**File:** `Exercise_28_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char *first_name;
	char *last_name;
	int age;
} User;

User *find_user(const char *username) {
	
	// No check if username == NULL

	if ( username == NULL )
	{
		return NULL;
	}

	if (strcmp(username, "john") == 0) {
		
		// No check if u == NULL after below calloc()

		User *u = calloc(1, sizeof(User));

		if ( u == NULL )
		{
			return NULL;
		}

		// Must first calloc() first_name and last_name

		u->first_name = (char*)calloc(5,sizeof(char));

		if ( u->first_name == NULL )
		{
			free(u);

			return NULL;
		}

		snprintf(u->first_name,5*sizeof(char),"%s","John");
		
		u->last_name = (char*)calloc(4,sizeof(char));

		if ( u->last_name == NULL )
		{
			free(u->first_name);

			free(u);

			return NULL;
		}
		
		snprintf(u->last_name,4*sizeof(char),"%s","Doe");

		u->age = 30;

		return u;
	}
	
	return NULL;
}

void print_user_info(const char *username) {
	
	// No check if find_user() returns NULL

	User *user = find_user(username);

	if ( user == NULL )
	{
		return;
	}

	printf("Name: %s %s, Age: %d\n", 
		user->first_name, 
		user->last_name, 
		user->age);

	// Have to free user->first_name first	
	// Have to free user->last_name next

	free(user->first_name);

	free(user->last_name);
 
	free(user);
}

int main() {
	print_user_info("john");
	print_user_info("alice");
	
	return 0;
}
```

---

## Solution 24: Exercise 29: C Security Audit - Code Review

**File:** `Exercise_29_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *format_log_message(const char *level, const char *message) {
	if (level == NULL || message == NULL) {
		return NULL;
	}
	
	// Below use of sprintf at risk of buffer overflow

	// Should use snprintf that uses buffer

	// capacity == strlen(level) + strlen(msg) + 3 (brackets+space) + 1	

	size_t capacity = 0;

	if ( __builtin_add_overflow(strlen(level),strlen(message),&capacity) == true )
	{
		return NULL;
	}

	size_t three = 3, one = 1;
	
	if ( __builtin_add_overflow(capacity,three,&capacity) == true )
	{
		return NULL;
	}
	
	if ( __builtin_add_overflow(capacity,one,&capacity) == true )
	{
		return NULL;
	}

	// assign buffer with calloc() below
	
	char * result = (char*) calloc(capacity,sizeof(char));

	if ( result == NULL )
	{
		return NULL;
	}

	// replacing sprintf() with snprintf()
	
	snprintf(result,capacity,"[%s] %s",level,message);

	return result;
}

int main() {
	char *log1 = format_log_message("INFO", "System started");
	char *log2 = format_log_message("ERROR", "Connection failed");
	
	if (log1 != NULL) {
		printf("%s\n", log1);
		free(log1);
	}
	
	if (log2 != NULL) {
		printf("%s\n", log2);
		free(log2);
	}
	
	return 0;
}
```

---

## Solution 25: Exercise 30: C Security Audit - Code Review

**File:** `Exercise_30_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

int get_matrix_element(int * matrix, size_t rows, size_t cols, size_t row, size_t col) {
	if (matrix == NULL || row >= rows || col >= cols) {
		return -1;
	}
	
	size_t index = 0; 

	if ( __builtin_mul_overflow(row,cols,&index) ==  true)
	{
		return -1;
	}
	
	if ( __builtin_add_overflow(index,col,&index) ==  true)
	{
		return -1;
	}
	
	return matrix[index];
}

int main() {
	int matrix[3][4] = {
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12}
	};

	int result = get_matrix_element((int*)matrix, 3, 4, 1, 2);

	if ( result != -1 )
	{
		printf("Element at (1, 2): %d\n",result);

	}

	result = get_matrix_element((int*)matrix, 3, 4, 2, 3);

	if ( result != -1 )
	{
		printf("Element at (2, 3): %d\n",result);

	}	
	
	return 0;
}
```

---

## Solution 26: Exercise 31: C Security Audit - Code Review

**File:** `Exercise_31_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int *copy_array(int *source, size_t count) {
	if (source == NULL || count == 0) {
		return NULL;
	}

	// incorrect count of bytes below	

	int * result = (int*)calloc(count,sizeof(int));
	
	if (result == NULL) {
		return NULL;
	}
	
	// incorrect count of bytes below	

	memcpy(result, source,count * sizeof(int));
	
	return result;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	int *copy = copy_array(numbers, 5);
	
	if (copy != NULL) {
		printf("Copied array: ");
		for (int i = 0; i < 5; i++) {
			printf("%d ", copy[i]);
		}
		printf("\n");
		free(copy);
	}
	
	return 0;
}
```

---

## Solution 27: Exercise 32: C Security Audit - Code Review

**File:** `Exercise_32_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *pad_string(const char *str, size_t width) {
	if (str == NULL || width == 0) {
		return NULL;
	}
	
	size_t len = strlen(str);
	
	if (len >= width) {
		return strdup(str);
	}

	// New size of result should be  width + 1 (watch out for Integer
	// Overflow)

	size_t newsize = 0;

	if ( __builtin_add_overflow(width,1,&newsize) == true )
	{
		return NULL;
	}
	
	char *result = calloc(newsize, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}

	snprintf(result,newsize,"%s",str);

	for ( size_t i = len ; i < (newsize - 1) ; i++ )
	{
		result[i] = ' ';
	} 
	
	// strcpy(result, str);
	
	// this is a really a bad way of trying to pad

	
	return result;
}

int main() {
	char *padded = pad_string("Hello", 10);
	
	if (padded != NULL) {
		printf("Padded: '%s'\n", padded);
		free(padded);
	}
	
	return 0;
}
```

---

## Solution 28: Exercise 33: C Security Audit - Code Review

**File:** `Exercise_33_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

void count_letters(const char *text) {
	if (text == NULL) {
		return;
	}

	// potential for overflow: better to use size_t
	
	size_t counts[26] = {0};

	// So what if text[i] is not an alphabetic letter?

	// this can cause possible out-of-bounds indexing
	
	for (size_t i = 0; i < strlen(text); i++) {

		if ( !isalpha(text[i]) )
		{
			continue;
		}

		char c = tolower(text[i]);

		// let's use size_t below instead of int

		size_t index = c - 'a';

		counts[index]++;
	}
	
	printf("Letter frequencies:\n");

	// let's use size_t below instead of int

	for (size_t i = 0; i < 26; i++) {
		if (counts[i] > 0) {
			printf("%c: %d\n", 'a' + i, counts[i]);
		}
	}
}

int main() {
	count_letters("Hello World!");
	
	return 0;
}
```

---

## Solution 29: Exercise 34: C Security Audit - Code Review

**File:** `Exercise_34_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void write_integers(unsigned char *buffer, size_t buffer_size,int *data, size_t count) {
	if (buffer == NULL || data == NULL || count == 0) {
		return;
	}

	// No check if buffer has enough space for data
	
	// There is enough space if buffer_size == count * sizeof(int)

	if ( buffer_size != count * sizeof(int) )
	{
		return;
	}

	memcpy(buffer,data,count * sizeof(int));
	
}

int main() {
	int numbers[] = {0x12345678, 0xABCDEF00, 0x11223344};
	unsigned char buffer[12];
	
	write_integers(buffer, 12 * sizeof(char),numbers, 3);
	
	printf("Buffer contents: ");
	for (int i = 0; i < 12; i++) {
		printf("%02X ", buffer[i]);
	}
	printf("\n");
	
	return 0;
}
```

---

## Solution 30: Exercise 35: C Security Audit - Code Review

**File:** `Exercise_35_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

typedef enum {
	ROLE_GUEST,
	ROLE_USER,
	ROLE_ADMIN
} UserRole;

bool check_access(UserRole role, const char *resource) {
	if (resource == NULL) {
		return false;
	}
	
	bool can_access = false;


	// No breaks after each switch conditional
	
	switch (role) {
		case ROLE_GUEST:
			if (strcmp(resource, "public") == 0) {
				can_access = true;
			}

			break;
		case ROLE_USER:
			if (strcmp(resource, "documents") == 0) {
				can_access = true;
			}

			break;
		case ROLE_ADMIN:
			if (strcmp(resource, "settings") == 0) {
				can_access = true;
			}

			break;

		// No check if resource has invalid value

		default:
		{
			can_access = false;

			break;
		}
	}
	
	return can_access;
}

int main() {
	printf("Guest accessing public: %s\n", 
		check_access(ROLE_GUEST, "public") ? "ALLOWED" : "DENIED");
	
	printf("Guest accessing settings: %s\n", 
		check_access(ROLE_GUEST, "settings") ? "ALLOWED" : "DENIED");
	
	printf("User accessing documents: %s\n", 
		check_access(ROLE_USER, "documents") ? "ALLOWED" : "DENIED");
	
	return 0;
}
```

---

## Solution 31: Exercise 34: C Security Audit - Code Review

**File:** `Exercise_36_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char hostname[32];
	int port;
} Config;

void set_hostname(Config *config, const char *hostname) {
	if (config == NULL || hostname == NULL) {
		return;
	}

	// Possible Buffer Overflow: hostname may be shorter than

	// the 32 bytes required
	
	// No guarantee terminating NULL-byte set after copying.

	// strncpy will only copy up to terminating NULL-byte

	// in source string

	// or until the requested number of bytes is copied

	snprintf(config->hostname,32*sizeof(char),"%s",hostname);
	
	//strncpy(config->hostname, hostname, sizeof(config->hostname));
}

int main() {
	Config config;
	config.port = 8080;
	
	set_hostname(&config, "server.example.com");
	
	printf("Hostname: %s\n", config.hostname);
	printf("Port: %d\n", config.port);
	
	return 0;
}
```

---

## Solution 32: Exercise 37: C Security Audit - Code Review

**File:** `Exercise_37_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int read_buffer(unsigned char *buffer, size_t buffer_size, size_t offset, unsigned char *output, size_t output_size) {
	if (buffer == NULL || output == NULL) {
		return -1;
	}

	// Integer Overflow Risk: use size_t for offset.

	// No reason to use a signed integer: offset can be negative

	// if using a signed integer!

	if (offset < 0 || offset >= buffer_size) {
		return -1;
	}
	
	if (output_size > buffer_size - offset) {
		return -1;
	}
	
	memcpy(output, buffer + offset, output_size);
	
	return 0;
}

int main() {

	// good habit to initialize arrays first

	unsigned char data[100] = {0};

	// bad habit to use a signed integer for counting

	// use size_t instead

	for (size_t i = 0; i < 100; i++) {
		data[i] = i;
	}

	// good habit to initialize arrays first
	
	unsigned char result[10] = {0};
	
	if (read_buffer(data, 100, 50, result, 10) == 0) {
		printf("Read succeeded: ");
		
		// bad habit to use a signed integer for counting

		// use size_t instead

		for (size_t i = 0; i < 10; i++) {
			printf("%d ", result[i]);
		}
		printf("\n");
	}
	
	return 0;
}
```

---

## Solution 33: Exercise 38: C Security Audit - Code Review

**File:** `Exercise_38_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char *name;
	char *value;
} ConfigEntry;

ConfigEntry *create_config(const char *name, const char *value) {
	if (name == NULL || value == NULL) {
		return NULL;
	}
		
	ConfigEntry *entry = malloc(sizeof(ConfigEntry));
	if (entry == NULL) {
		return NULL;
	}

	// No check if either strdup() returns NULL below
	
	entry->name = strdup(name);

	if ( entry->name == NULL )
	{
		free(entry);

		return NULL;
	}

	entry->value = strdup(value);

	if ( entry->value == NULL )
	{
		free(entry->name);

		free(entry);

		return NULL;
	}
	
	return entry;
}

// No attempt at error-handling for below function
int update_config(ConfigEntry *entry, const char *new_value) {

	if (entry == NULL || new_value == NULL) {
		return 1;
	}
	
	// No check if entry->value == NULL first before doing below

	if ( entry->value != NULL )
	{	
		free(entry->value);
	}

	// No check if strdup() returns NULL

	entry->value = strdup(new_value);

	if ( entry->value == NULL )
	{
		return 1;
	}

	return 0;
}

void free_config(ConfigEntry *entry) {
	if (entry == NULL) {
		return;
	}
	
	// No attempt to check if any of the fields below point to NULL	

	// before attempting to free

	if ( entry->name != NULL )	
	{
		free(entry->name);
	}

	if ( entry->value != NULL )
	{
		free(entry->value);
	}

	free(entry);
}

int main() {

	// No attempt to check if create_config returned NULL

	ConfigEntry *config = create_config("hostname", "localhost");

	if ( config == NULL )
	{
		return 1;
	}
	
	printf("Initial: %s = %s\n", config->name, config->value);
	
	if ( update_config(config, "server.example.com") != 0 )
	{
		return 1;
	}
	
	printf("Updated: %s = %s\n", config->name, config->value);
	
	free_config(config);
	
	return 0;
}
```

---

## Solution 34: ACME Product Security Tech Test - Question 1

**File:** `Exercise_39_Code_Review.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

char *deserialize(const char *s) {
	
	// No attempt at error-handling: if any of the

	// operations below fail it would be wise to return

	// NULL. Instead function assumes all operations

	// work without failure.

	// No check if s == NULL. This can cause the computer

	// to attempt to dereference a NULL pointer. This is

	// dangerous behavior.

	if ( s == NULL )
	{
		return NULL;
	}
	
	size_t len = strnlen(s, 4096);
	
	// Off-by-One Error:

	// forgot to add extra byte for terminal NULL-byte below

	// When adding extra byte for space in length watch

	// out for Integer Overflow Possibility

	// Failed to check if malloc() returns NULL: this can

	// cause the computer to attempt to dereference a NULL

	// pointer. This is dangerous behavior.

	size_t alloc_len = 0;

	if ( __builtin_add_overflow(len,1,&alloc_len) == true )
	{
		return NULL;
	}

	char *b = (char *) calloc(alloc_len,sizeof(char));

	if ( b == NULL )
	{
		return NULL;
	}

	// strcpy() unsafe: does not gurantee NULL-termination

	// after copying

	// Buffer Overflow: Also strcpy will attempt to copy entire

	// contents of s to b. It's possible s is longer than b.

	if ( snprintf(b,alloc_len,"%s",s) < 0 )
	{
		free(b);

		return NULL;	
	}

	return b;
}
```

---

## Solution 35: ACME Product Security Tech Test - Question 1

**File:** `ACME_Question_1.md`

```c
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

char *deserialize(const char *s) {
	
	// No attempt at error-handling: if any of the

	// operations below fail it would be wise to return

	// NULL. Instead function assumes all operations

	// work without failure.

	// No check if s == NULL. This can cause the computer

	// to attempt to dereference a NULL pointer. This is

	// dangerous behavior.

	if ( s == NULL )
	{
		return NULL;
	}
	
	size_t len = strnlen(s, 4096);
	
	// Off-by-One Error:

	// forgot to add extra byte for terminal NULL-byte below

	// When adding extra byte for space in length watch

	// out for Integer Overflow Possibility

	// Failed to check if malloc() returns NULL: this can

	// cause the computer to attempt to dereference a NULL

	// pointer. This is dangerous behavior.

	size_t alloc_len = 0;

	if ( __builtin_add_overflow(len,1,&alloc_len) == true )
	{
		return NULL;
	}

	char *b = (char *) calloc(alloc_len,sizeof(char));

	if ( b == NULL )
	{
		return NULL;
	}

	// strcpy() unsafe: does not gurantee NULL-termination

	// after copying

	// Buffer Overflow: Also strcpy will attempt to copy entire

	// contents of s to b. It's possible s is longer than b.

	if ( snprintf(b,alloc_len,"%s",s) < 0 )
	{
		free(b);

		return NULL;	
	}

	return b;
}
```

---

## Want More Practice?

🔗 **[SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises)**

- ⭐ Star the repo if you found this useful!
- 💬 Open issues to discuss solutions
- 🔀 Contribute more exercises

**These exercises prepare you for Security Engineering interviews at top companies.**

---

## The Bottom Line

The Ariane 5 explosion. Heartbleed. WannaCry. Stagefright. Dirty COW.

**Every one was preventable with proper code review.**

Security Engineering isn't about memorizing vulnerability types. It's about developing the instinct to spot dangerous patterns in production code.

These 35 exercises represent 35 patterns that have caused real breaches, real outages, and real damage. Master them, and you'll be ahead of 90% of developers.

**The best time to learn was before production. The second best time is now.**
