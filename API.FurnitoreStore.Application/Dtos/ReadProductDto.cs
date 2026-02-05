using System;

namespace API.FurnitoreStore.Application.Dtos;

public class ReadProductDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public decimal Price { get; set; }
    public int ProductCategoryId { get; set; }
}