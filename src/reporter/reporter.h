// SPDX-License-Identifier: MIT
#ifndef SP_DIFFER_REPORTER_REPORTER_H
#define SP_DIFFER_REPORTER_REPORTER_H

#include <string>
#include <vector>

namespace sp_differ {

struct CaseReport {
  std::string case_path;
  int case_format_version = 0;
  std::string execution_mode;
  std::string implementation;
  std::string expected_path;
  std::string source_id;
  std::string semantic_status;
  bool passed = false;
  std::string detail;
};

struct SuiteReport {
  std::string worker;
  std::string semantic_worker;
  std::string suite_name;
  int total_count = 0;
  int passed_count = 0;
  int failed_count = 0;
  std::vector<CaseReport> cases;
};

bool WriteSuiteReportJson(const SuiteReport& report, const std::string& path,
                          std::string* error);
bool WriteSuiteReportMarkdown(const SuiteReport& report, const std::string& path,
                              std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_REPORTER_REPORTER_H
