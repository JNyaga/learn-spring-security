package com.ropro.learn_spring_security.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoResource {
    private Logger logger = LoggerFactory.getLogger(getClass());

    private static final List<Todo> TODO_LIST = List.of(
            new Todo("John", "Learn Spring Boot"),
            new Todo("Perry", "Growth Hacking"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return TODO_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodoForSPecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Creat {} for {}", todo, username);
    }

}

record Todo(String username, String description) {
}