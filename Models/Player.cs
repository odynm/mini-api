﻿namespace MinimalApi.Models
{
    public class Player
    {
        public Guid Id { get; set; }
        public string? Name { get; set; }
        public bool Active { get; set; }
    }
}
