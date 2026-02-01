using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitoreStore.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ProductCategoriesController (IProductCategoriesService productCategoryService): ControllerBase
    {
        [HttpGet]
        public async Task<IEnumerable<ProductCategory>> GetCategories()
        {
            return await productCategoryService.GetAllAsync();
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetDetails(int id)
        {
            var prodCategory = await productCategoryService.GetByIdAsync(id);
            if (prodCategory == null) 
                return NotFound();
            return Ok(prodCategory);
        }

        [HttpPost]
        public async Task<IActionResult> Post(ProductCategory prodCategory)
        {
            if (prodCategory == null) 
                return BadRequest();

            await productCategoryService.CreateAsync(prodCategory);
            return CreatedAtAction("Post", prodCategory.Id, prodCategory);
        }

        [HttpPut]
        public async Task<IActionResult> Put (ProductCategory prodCategory)
        {
            productCategoryService.UpdateAsync(prodCategory);
            return NoContent();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(ProductCategory prodCategory)
        {
            if (prodCategory == null)
                return NotFound();
            await productCategoryService.DeleteAsync(prodCategory.Id);
            return NoContent();
        }
    }
}
