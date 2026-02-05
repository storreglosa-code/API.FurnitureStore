using API.FornitureStore.Data;
using API.FurnitoreStore.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using API.FurnitoreStore.Application.Interfaces;

namespace API.FurnitoreStore.API.Controllers
{
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
        public async Task<IEnumerable<Product>> Get()
        {
            return await _productsService.GetAllAsync();
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetDetails(int id)
        {
            var product = await _productsService.GetByIdAsync(id);

            if (product == null)
                return BadRequest();

            return Ok(product);
        }

        [HttpGet("GetByCategory/{productCategoryId}")]
        public async Task<IEnumerable<Product>> GetByCategory(int productCategoryId)
        {
            var products = await _productsService.GetAllAsync();
            return products.Where(p => p.ProductCategoryId == productCategoryId);
        }

        [HttpPost]
        public async Task<IActionResult> Post(Product product)
        {
            if (product == null)
                return BadRequest();

            await _productsService.CreateAsync(product);
            return CreatedAtAction("Post", product.Id, product);
        }

        [HttpPut]
        public async Task<IActionResult> Update(Product product)
        {
            if (product == null)
                return NotFound();

            await _productsService.UpdateAsync(product);
            return NoContent();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(Product product)
        {
            if (product == null)
                return NotFound();

            await _productsService.DeleteAsync(product.Id);
            return NoContent();
        }
    }
}
