using System;

namespace API.FurnitoreStore.Application.Dtos.Product;

public class CreateProductDto
{
    public string Name { get; set; } = string.Empty;
    public decimal Price { get; set; }
    public int ProductCategoryId { get; set; }
}