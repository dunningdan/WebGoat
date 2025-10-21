/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.sql.*;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlInjectionChallenge1",
      "SqlInjectionChallenge2",
      "SqlInjectionChallenge3",
      "SqlInjectionChallenge4",
      "SqlInjectionChallenge5",
      "SqlInjectionChallenge6",
      "SqlInjectionChallenge7"
    })
@Slf4j
public class SqlInjectionChallenge implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionChallenge(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PutMapping("/SqlInjectionAdvanced/register")
  // assignment path is bounded to class so we use different http method :-)
  @ResponseBody
  public AttackResult registerNewUser(
      @RequestParam("username_reg") String username,
      @RequestParam("email_reg") String email,
      @RequestParam("password_reg") String password) {
    AttackResult attackResult = checkArguments(username, email, password);

    if (attackResult == null) {

      try (Connection connection = dataSource.getConnection()) {
        String checkUserQuery =
            "select userid from sql_challenge_users where userid = '" + username + "'";
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(checkUserQuery);

        if (resultSet.next()) {
          attackResult = failed(this).feedback("user.exists").feedbackArgs(username).build();
        } else {
          PreparedStatement preparedStatement =
              connection.prepareStatement("INSERT INTO sql_challenge_users VALUES (?, ?, ?)");
          preparedStatement.setString(1, username);
          preparedStatement.setString(2, email);
          preparedStatement.setString(3, password);
          preparedStatement.execute();
          attackResult =
              informationMessage(this).feedback("user.created").feedbackArgs(username).build();
        }
      } catch (SQLException e) {
        attackResult = failed(this).output("Something went wrong").build();
      }
    }
    return attackResult;
  }

  private AttackResult checkArguments(String username, String email, String password) {
    if (StringUtils.isEmpty(username)
        || StringUtils.isEmpty(email)
        || StringUtils.isEmpty(password)) {
      return failed(this).feedback("input.invalid").build();
    }
    if (username.length() > 250 || email.length() > 30 || password.length() > 30) {
      return failed(this).feedback("input.invalid").build();
    }
    return null;
  }

  /**
   * VULNERABLE ENDPOINT - Demonstrates SQL Injection vulnerability
   * This endpoint is intentionally vulnerable to demonstrate security scanning
   */
  @GetMapping("/SqlInjectionAdvanced/searchUser")
  @ResponseBody
  public AttackResult searchUser(@RequestParam("searchTerm") String searchTerm) {
    try (Connection connection = dataSource.getConnection()) {
      // VULNERABILITY: SQL Injection - Direct string concatenation
      String vulnerableQuery = "SELECT userid, email FROM sql_challenge_users WHERE userid LIKE '%" + searchTerm + "%' OR email LIKE '%" + searchTerm + "%'";

      Statement statement = connection.createStatement();
      ResultSet resultSet = statement.executeQuery(vulnerableQuery);

      StringBuilder results = new StringBuilder();
      int count = 0;
      while (resultSet.next()) {
        results.append("User: ").append(resultSet.getString("userid"))
               .append(", Email: ").append(resultSet.getString("email"))
               .append("\n");
        count++;
      }

      if (count > 0) {
        return informationMessage(this)
            .feedback("Found " + count + " user(s):\n" + results.toString())
            .build();
      } else {
        return informationMessage(this)
            .feedback("No users found matching: " + searchTerm)
            .build();
      }
    } catch (SQLException e) {
      log.error("SQL error in searchUser", e);
      return failed(this).output("Database error: " + e.getMessage()).build();
    }
  }
}
