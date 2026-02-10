using System;

namespace API.FurnitoreStore.Application.Dtos.Client;

public class ReadClientDto
{
    public int Id { get; set; }
    public Guid AspNetUserId { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime BirthDate { get; set; }
    public string Phone { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
}