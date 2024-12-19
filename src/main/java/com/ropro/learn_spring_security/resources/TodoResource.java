package com.ropro.learn_spring_security.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController // Marks this class as a REST controller to handle HTTP requests
public class TodoResource {
    private Logger logger = LoggerFactory.getLogger(getClass()); // Logger instance for logging information

    // Static list of TODOs to simulate a database
    private static final List<Todo> TODO_LIST = List.of(
            new Todo("John", "Learn Spring Boot"),
            new Todo("Perry", "Growth Hacking"));

    @GetMapping("/todos") // Handles GET requests to "/todos"
    public List<Todo> retrieveAllTodos() {
        return TODO_LIST; // Returns the entire list of TODOs
    }

    @GetMapping("/users/{username}/todos") // Handles GET requests to "/users/{username}/todos"
    @PreAuthorize("hasRole('USER') and #username == authentication.name") // Checks user role and if the username
                                                                          // matches the authenticated user
    @PostAuthorize("returnObject.username =='joel'") // Ensures the returned TODO is for the user "joel"
    @RolesAllowed({ "ADMIN", "USER" }) // Specifies roles allowed to access this method
    @Secured({ "ROLE_ADMIN", "ROLE_USER" }) // Another way to specify role-based access control
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODO_LIST.get(0); // Returns the first TODO for simplicity
    }

    @PostMapping("/users/{username}/todos") // Handles POST requests to "/users/{username}/todos"
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        // Logs the creation of a TODO for a specific user
        logger.info("Create {} for {}", todo, username);
    }

}

// Record class to represent a TODO object with username and description fields
record Todo(String username, String description) {
}
