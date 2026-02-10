using API.FornitureStore.Data;
using API.FurnitoreStore.Share;
using API.FurnitoreStore.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using API.FurnitoreStore.Application.Dtos.Product;

namespace API.FurnitoreStore.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ProductsController : ControllerBase
{
    private readonly IProductsService _productsService;

    public ProductsController(IProductsService productsService)
    {
        _productsService = productsService;
    }

    [HttpGet]
    public async Task<IEnumerable<ReadProductDto>> Get()
    {
        return await _productsService.GetAllAsync();
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetDetails(int id)
    {
        var product = await _productsService.GetByIdAsync(id);

        if (product == null)
            return NotFound();

        return Ok(product);
    }

    [HttpGet("GetByCategory/{productCategoryId}")]
    public async Task<IEnumerable<ReadProductDto>> GetByCategory(int productCategoryId)
    {
        var products = await _productsService.GetAllAsync();
        return products.Where(p => p.ProductCategoryId == productCategoryId);
    }

    [HttpPost]
    public async Task<IActionResult> Post(CreateProductDto createDto)
    {
        if (createDto == null)
            return BadRequest();

        var created = await _productsService.CreateAsync(createDto);
        return CreatedAtAction(nameof(GetDetails), new { id = created.Id }, created);
    }

    [HttpPut]
    public async Task<IActionResult> Update(UpdateProductDto updateDto)
    {
        if (updateDto == null)
            return BadRequest();

        await _productsService.UpdateAsync(updateDto);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        if (id <= 0)
            return BadRequest();

        await _productsService.DeleteAsync(id);
        return NoContent();
    }
}
